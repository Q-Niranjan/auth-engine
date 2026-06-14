import logging
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, status

from auth_engine.core import mongodb
from auth_engine.schemas.contact import ContactLeadCreate

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/contact", status_code=status.HTTP_201_CREATED)
async def submit_contact_lead(
    payload: ContactLeadCreate,
    request: Request,
) -> dict[str, str]:
    if not payload.consent:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Consent is required to submit this form.",
        )

    db = mongodb.mongo_db
    if db is None:
        logger.error("MongoDB unavailable — cannot save contact lead")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Contact form is temporarily unavailable. Please try again later.",
        )

    doc = {
        **payload.model_dump(),
        "created_at": datetime.now(UTC),
        "source": "marketing_contact_form",
        "ip_address": request.client.host if request.client else None,
        "user_agent": request.headers.get("user-agent"),
    }

    await db["contact_leads"].insert_one(doc)
    logger.info("Contact lead saved for %s at %s", payload.email, payload.company)

    return {"message": "Thanks! Our team will reach out within 1 business day."}
