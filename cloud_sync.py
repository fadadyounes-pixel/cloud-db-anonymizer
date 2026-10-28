"""
Single-target cloud upload for sanitized dumps (free edition).

Works with any S3-compatible bucket: AWS S3, Cloudflare R2, DigitalOcean Spaces,
MinIO, Backblaze B2, Wasabi... Credentials come from the standard AWS
environment variables / ~/.aws config, so nothing secret ever lives in rules.json.

The Pro Suite adds parallel multi-cloud fan-out, retention pruning, scheduled
runs, a web dashboard and Telegram/Discord alerts.
"""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional


@dataclass
class UploadResult:
    bucket: str
    key: str
    bytes: int
    uri: str


def upload_file(
    path: str | Path,
    bucket: str,
    key: Optional[str] = None,
    prefix: str = "",
    endpoint_url: Optional[str] = None,
    region: Optional[str] = None,
    on_progress: Callable[[int], None] | None = None,
) -> UploadResult:
    """Upload one file to an S3-compatible bucket using multipart transfer."""
    try:
        import boto3
        from boto3.s3.transfer import TransferConfig
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("boto3 is required for cloud sync: pip install boto3") from exc

    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(path)

    key = key or (prefix.strip("/") + "/" if prefix.strip("/") else "") + path.name
    client = boto3.client(
        "s3",
        endpoint_url=endpoint_url or os.getenv("S3_ENDPOINT_URL") or None,
        region_name=region or os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or None,
    )

    lock = threading.Lock()

    def _cb(n: int) -> None:
        if on_progress:
            with lock:
                on_progress(n)

    client.upload_file(
        str(path),
        bucket,
        key,
        Callback=_cb,
        Config=TransferConfig(multipart_threshold=16 * 1024 * 1024, max_concurrency=4),
        ExtraArgs={"ServerSideEncryption": "AES256"} if not endpoint_url and not os.getenv("S3_ENDPOINT_URL") else None,
    )
    return UploadResult(bucket=bucket, key=key, bytes=path.stat().st_size, uri=f"s3://{bucket}/{key}")
