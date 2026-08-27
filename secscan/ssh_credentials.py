from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
import sqlite3
from uuid import uuid4

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import serialization

from secscan.scanners.linux_host import validate_ssh_user


@dataclass(frozen=True)
class SshCredentialProfile:
    id: str
    name: str
    username: str
    is_default: bool
    created_at: str
    updated_at: str

    def as_public_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class DecryptedSshCredential:
    profile: SshCredentialProfile
    private_key: str
    known_hosts: str


class SshCredentialStore:
    def __init__(self, database: Path, master_key: str) -> None:
        self.database = database.expanduser().resolve()
        try:
            self._fernet = Fernet(master_key.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise ValueError("SECSCAN_CREDENTIAL_KEY must be a valid Fernet key") from exc
        self._migrate()

    def _connect(self) -> sqlite3.Connection:
        self.database.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.database)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _migrate(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS ssh_credential_profiles (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    username TEXT NOT NULL,
                    private_key_ciphertext BLOB NOT NULL,
                    known_hosts_ciphertext BLOB NOT NULL,
                    is_default INTEGER NOT NULL DEFAULT 0 CHECK (is_default IN (0, 1)),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE UNIQUE INDEX IF NOT EXISTS ssh_credential_single_default_idx
                    ON ssh_credential_profiles(is_default) WHERE is_default = 1;
                CREATE TABLE IF NOT EXISTS ssh_host_credentials (
                    host TEXT PRIMARY KEY,
                    profile_id TEXT NOT NULL REFERENCES ssh_credential_profiles(id) ON DELETE CASCADE,
                    updated_at TEXT NOT NULL
                );
                """
            )

    @staticmethod
    def _timestamp() -> str:
        return datetime.now(UTC).isoformat()

    @staticmethod
    def _validate_name(name: str) -> str:
        value = name.strip()
        if not value or len(value) > 80 or any(character.isspace() and character not in " \t" for character in value):
            raise ValueError("credential profile name must contain 1-80 printable characters")
        return value

    @staticmethod
    def _validate_private_key(private_key: str) -> str:
        value = private_key.strip() + "\n"
        data = value.encode("utf-8")
        loaded = False
        for loader in (serialization.load_ssh_private_key, serialization.load_pem_private_key):
            try:
                loader(data, password=None)
                loaded = True
                break
            except (ValueError, TypeError):
                continue
        if not loaded:
            raise ValueError("SSH private key must be a valid unencrypted OpenSSH or PEM private key")
        return value

    @staticmethod
    def _validate_known_hosts(known_hosts: str) -> str:
        value = known_hosts.strip() + "\n"
        if len(value) > 1024 * 1024:
            raise ValueError("known_hosts content must not exceed 1 MiB")
        lines = [line.strip() for line in value.splitlines() if line.strip() and not line.lstrip().startswith("#")]
        if not lines:
            raise ValueError("known_hosts must contain at least one trusted host-key entry")
        if any(len(line.split()) < 2 for line in lines):
            raise ValueError("known_hosts contains a malformed host-key entry")
        return value

    @staticmethod
    def _profile(row: sqlite3.Row) -> SshCredentialProfile:
        return SshCredentialProfile(
            id=str(row["id"]),
            name=str(row["name"]),
            username=str(row["username"]),
            is_default=bool(row["is_default"]),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
        )

    def create(
        self,
        *,
        name: str,
        username: str,
        private_key: str,
        known_hosts: str,
        is_default: bool = False,
    ) -> SshCredentialProfile:
        profile_id = str(uuid4())
        validated_name = self._validate_name(name)
        validated_user = validate_ssh_user(username)
        validated_key = self._validate_private_key(private_key)
        validated_hosts = self._validate_known_hosts(known_hosts)
        timestamp = self._timestamp()
        with self._connect() as connection:
            try:
                if is_default:
                    connection.execute("UPDATE ssh_credential_profiles SET is_default = 0, updated_at = ? WHERE is_default = 1", (timestamp,))
                connection.execute(
                    """
                    INSERT INTO ssh_credential_profiles (
                        id, name, username, private_key_ciphertext, known_hosts_ciphertext,
                        is_default, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        profile_id,
                        validated_name,
                        validated_user,
                        self._fernet.encrypt(validated_key.encode("utf-8")),
                        self._fernet.encrypt(validated_hosts.encode("utf-8")),
                        1 if is_default else 0,
                        timestamp,
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("credential profile name already exists") from exc
        profile = self.get(profile_id)
        assert profile is not None
        return profile

    def list(self) -> list[SshCredentialProfile]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT id, name, username, is_default, created_at, updated_at
                FROM ssh_credential_profiles
                ORDER BY is_default DESC, name COLLATE NOCASE, id
                """
            ).fetchall()
        return [self._profile(row) for row in rows]

    def get(self, profile_id: str) -> SshCredentialProfile | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT id, name, username, is_default, created_at, updated_at
                FROM ssh_credential_profiles WHERE id = ?
                """,
                (profile_id,),
            ).fetchone()
        return self._profile(row) if row else None

    def decrypt(self, profile_id: str) -> DecryptedSshCredential:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM ssh_credential_profiles WHERE id = ?", (profile_id,)).fetchone()
        if row is None:
            raise ValueError("SSH credential profile was not found")
        try:
            private_key = self._fernet.decrypt(bytes(row["private_key_ciphertext"])).decode("utf-8")
            known_hosts = self._fernet.decrypt(bytes(row["known_hosts_ciphertext"])).decode("utf-8")
        except (InvalidToken, UnicodeDecodeError) as exc:
            raise ValueError("SSH credential profile could not be decrypted with the configured master key") from exc
        return DecryptedSshCredential(self._profile(row), private_key, known_hosts)

    def set_default(self, profile_id: str) -> SshCredentialProfile:
        timestamp = self._timestamp()
        with self._connect() as connection:
            exists = connection.execute("SELECT 1 FROM ssh_credential_profiles WHERE id = ?", (profile_id,)).fetchone()
            if exists is None:
                raise ValueError("SSH credential profile was not found")
            connection.execute("UPDATE ssh_credential_profiles SET is_default = 0, updated_at = ? WHERE is_default = 1", (timestamp,))
            connection.execute("UPDATE ssh_credential_profiles SET is_default = 1, updated_at = ? WHERE id = ?", (timestamp, profile_id))
        profile = self.get(profile_id)
        assert profile is not None
        return profile

    def delete(self, profile_id: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute("DELETE FROM ssh_credential_profiles WHERE id = ?", (profile_id,))
        return cursor.rowcount > 0

    def bind_host(self, host: str, profile_id: str) -> None:
        if self.get(profile_id) is None:
            raise ValueError("SSH credential profile was not found")
        timestamp = self._timestamp()
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO ssh_host_credentials (host, profile_id, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(host) DO UPDATE SET profile_id = excluded.profile_id, updated_at = excluded.updated_at
                """,
                (host, profile_id, timestamp),
            )

    def resolve_profile_id(self, host: str) -> str | None:
        with self._connect() as connection:
            bound = connection.execute("SELECT profile_id FROM ssh_host_credentials WHERE host = ?", (host,)).fetchone()
            if bound is not None:
                return str(bound["profile_id"])
            default = connection.execute("SELECT id FROM ssh_credential_profiles WHERE is_default = 1").fetchone()
        return str(default["id"]) if default is not None else None
