from fastapi import APIRouter, Depends, HTTPException, Query, status

from auth_engine.api.dependencies.rbac import check_platform_permission
from auth_engine.core import mongodb
from auth_engine.models import UserORM
from auth_engine.schemas.contact import ContactLead

router = APIRouter()


@router.get(
    "/contact-leads",
    response_model=list[ContactLead],
    status_code=status.HTTP_200_OK,
)
async def list_contact_leads(
    email: str | None = Query(None, description="Filter by email (partial match)"),
    company: str | None = Query(None, description="Filter by company (partial match)"),
    limit: int = Query(50, ge=1, le=100),
    skip: int = Query(0, ge=0),
    current_user: UserORM = Depends(check_platform_permission("platform.leads.view")),
) -> list[ContactLead]:
    """List marketing contact form leads stored in MongoDB."""
    db = mongodb.mongo_db
    if db is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Lead storage is temporarily unavailable.",
        )

    query: dict[str, object] = {}
    if email:
        query["email"] = {"$regex": email, "$options": "i"}
    if company:
        query["company"] = {"$regex": company, "$options": "i"}

    try:
        cursor = db["contact_leads"].find(query).sort("created_at", -1).skip(skip).limit(limit)
        raw = await cursor.to_list(length=limit)
        leads: list[ContactLead] = []
        for doc in raw:
            doc["id"] = str(doc.pop("_id"))
            leads.append(ContactLead.model_validate(doc))
        return leads
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error retrieving contact leads: {str(e)}",
        ) from e
