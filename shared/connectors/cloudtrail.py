import logging
from time import perf_counter

logger = logging.getLogger(__name__)


class CloudTrailConnector:
    def __init__(self, aws_access_key_id: str = "", aws_secret_access_key: str = "", region: str = "us-east-1"):
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.region = region

    async def get_events(self, limit: int = 100) -> list[dict]:
        if not self.aws_access_key_id or not self.aws_secret_access_key:
            logger.warning("CloudTrail connector not configured (AWS credentials required)")
            return []
        try:
            import boto3
            client = boto3.client(
                "cloudtrail",
                region_name=self.region,
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
            )
            response = client.lookup_events(MaxResults=min(limit, 50))
            return response.get("Events", [])
        except ImportError:
            logger.error("boto3 not installed — cannot query CloudTrail")
            return []
        except Exception as exc:
            logger.error("CloudTrail fetch failed: %s", exc)
            return []

    async def health(self) -> dict:
        started = perf_counter()
        if not self.aws_access_key_id:
            return {"connected": False, "error": "CloudTrail not configured", "latency_ms": 0}
        try:
            import boto3
            client = boto3.client(
                "cloudtrail",
                region_name=self.region,
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
            )
            client.describe_trails()
            return {"connected": True, "latency_ms": round((perf_counter() - started) * 1000)}
        except ImportError:
            return {"connected": False, "error": "boto3 not installed", "latency_ms": 0}
        except Exception as exc:
            return {"connected": False, "error": str(exc), "latency_ms": round((perf_counter() - started) * 1000)}
