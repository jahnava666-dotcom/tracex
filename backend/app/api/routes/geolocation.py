from fastapi import APIRouter, Query, HTTPException, status
from ...services.geo_service import lookup_ip_geolocation, extract_ip_from_text
from ...core.security import GEOLOCATION_DISCLAIMER

router = APIRouter(tags=["Geolocation & Forensics"])

@router.get("/geolocation")
async def get_ip_geolocation(
    ip: str = Query(..., description="IPv4 or IPv6 address to geolocate")
):
    """
    Retrieve infrastructure geolocation and Autonomous System Network (ASN) routing for an IP address.
    Includes forensic confidence rating and legal disclaimer.
    """
    clean_ip = extract_ip_from_text(ip)
    if not clean_ip:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid IP address format provided."
        )

    geo_info = await lookup_ip_geolocation(clean_ip)
    return geo_info

@router.post("/geolocation")
async def post_ip_geolocation(
    payload: dict
):
    """
    Retrieve infrastructure geolocation via POST body.
    """
    ip = payload.get("ip") or payload.get("ip_address") or ""
    clean_ip = extract_ip_from_text(str(ip))
    if not clean_ip:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Valid 'ip' field is required in request body."
        )

    geo_info = await lookup_ip_geolocation(clean_ip)
    return geo_info
