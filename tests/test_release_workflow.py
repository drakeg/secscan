from pathlib import Path

import yaml


def _release_job() -> dict[str, object]:
    workflow_path = Path(__file__).parents[1] / ".github" / "workflows" / "release.yml"
    workflow = yaml.safe_load(workflow_path.read_text(encoding="utf-8"))
    return workflow["jobs"]["release"]


def test_release_job_scopes_container_publication_permissions() -> None:
    job = _release_job()

    assert job["permissions"] == {
        "attestations": "write",
        "contents": "write",
        "id-token": "write",
        "packages": "write",
    }
    assert job["env"] == {
        "REGISTRY": "ghcr.io",
        "IMAGE_NAME": "ghcr.io/${{ github.repository }}",
    }


def test_release_job_publishes_only_exact_version_and_records_digest() -> None:
    steps = _release_job()["steps"]
    by_id = {step["id"]: step for step in steps if "id" in step}

    qemu = next(step for step in steps if step["name"] == "Set up QEMU for ARM64")
    buildx = next(step for step in steps if step["name"] == "Set up Docker Buildx")
    assert qemu["uses"] == "docker/setup-qemu-action@v4"
    assert qemu["with"] == {"platforms": "arm64"}
    assert buildx["uses"] == "docker/setup-buildx-action@v4"
    assert steps.index(qemu) < steps.index(buildx)

    metadata = by_id["metadata"]
    assert metadata["uses"] == "docker/metadata-action@v6"
    assert metadata["with"]["images"] == "${{ env.IMAGE_NAME }}"
    assert metadata["with"]["flavor"] == "latest=false\n"
    assert metadata["with"]["tags"] == "type=semver,pattern={{version}}\n"

    container = by_id["container"]
    assert container["uses"] == "docker/build-push-action@v7"
    assert container["with"] == {
        "context": ".",
        "platforms": "linux/amd64,linux/arm64",
        "push": True,
        "provenance": False,
        "tags": "${{ steps.metadata.outputs.tags }}",
        "labels": "${{ steps.metadata.outputs.labels }}",
        "build-args": "SECSCAN_VERSION=${{ steps.metadata.outputs.version }}\n",
    }

    record = next(step for step in steps if step["name"] == "Record immutable container reference")
    assert record["env"]["CONTAINER_DIGEST"] == "${{ steps.container.outputs.digest }}"
    assert "release-dist/CONTAINER_IMAGE" in record["run"]
    assert '"$IMAGE_NAME" "$CONTAINER_DIGEST"' in record["run"]


def test_release_job_attests_the_published_registry_digest() -> None:
    steps = _release_job()["steps"]
    attestation = next(step for step in steps if step["name"] == "Attest container build provenance")

    assert attestation["uses"] == "actions/attest-build-provenance@v4"
    assert attestation["with"] == {
        "subject-name": "${{ env.IMAGE_NAME }}",
        "subject-digest": "${{ steps.container.outputs.digest }}",
        "push-to-registry": True,
    }
