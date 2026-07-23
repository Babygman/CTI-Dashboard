from datetime import date, datetime

from sqlalchemy.exc import IntegrityError

from app.extensions import db
from app.models.remediation_action import (
    ACTION_STATUSES,
    ACTION_TYPES,
    APPROVAL_STATUSES,
    PRIORITIES,
    RemediationAction,
)
from app.models.remediation_action_history import (
    RemediationActionHistory,
)
from app.repositories import RemediationActionRepository


EDITABLE_FIELDS = (
    "ThreatId",
    "Title",
    "Description",
    "ActionType",
    "Priority",
    "Status",
    "Owner",
    "DueDate",
    "ApprovalStatus",
    "TicketReference",
    "Notes",
)


class DuplicateRemediationActionError(ValueError):
    pass


class RemediationActionService:
    def __init__(self, repository=None):
        self.repository = repository or RemediationActionRepository()

    @staticmethod
    def parse_form(form):
        return {
            "ThreatId": (form.get("threat_id") or "").strip(),
            "Title": (form.get("title") or "").strip(),
            "Description": (form.get("description") or "").strip(),
            "ActionType": (form.get("action_type") or "").strip(),
            "Priority": (form.get("priority") or "").strip(),
            "Status": (form.get("status") or "").strip(),
            "Owner": (form.get("owner") or "").strip(),
            "DueDate": (form.get("due_date") or "").strip(),
            "ApprovalStatus": (
                form.get("approval_status") or ""
            ).strip(),
            "TicketReference": (
                form.get("ticket_reference") or ""
            ).strip(),
            "Notes": (form.get("notes") or "").strip(),
        }

    @staticmethod
    def validate(values):
        errors = {}
        try:
            values["ThreatId"] = int(values["ThreatId"])
        except (TypeError, ValueError):
            errors["threat_id"] = "Select a valid threat."

        if not values["Title"]:
            errors["title"] = "Title is required."
        elif len(values["Title"]) > 255:
            errors["title"] = "Title must be 255 characters or fewer."

        if values["ActionType"] not in ACTION_TYPES:
            errors["action_type"] = "Select a valid action type."
        if values["Priority"] not in PRIORITIES:
            errors["priority"] = "Select a valid priority."
        if values["Status"] not in ACTION_STATUSES:
            errors["status"] = "Select a valid status."
        if values["ApprovalStatus"] not in APPROVAL_STATUSES:
            errors["approval_status"] = (
                "Select a valid approval status."
            )
        if len(values["Owner"]) > 200:
            errors["owner"] = "Owner must be 200 characters or fewer."
        if len(values["TicketReference"]) > 255:
            errors["ticket_reference"] = (
                "Ticket reference must be 255 characters or fewer."
            )

        if values["DueDate"]:
            try:
                values["DueDate"] = date.fromisoformat(
                    values["DueDate"]
                )
            except ValueError:
                errors["due_date"] = "Enter a valid due date."
        else:
            values["DueDate"] = None
        return errors

    def create(self, values):
        self._check_duplicate(values)
        action = RemediationAction()
        self._assign(action, values)
        self._apply_completion_timestamp(action, None)
        db.session.add(action)
        db.session.flush()
        self._record(
            action,
            "Created",
            new_value=action.Status,
        )
        self._commit_with_duplicate_guard()
        return action

    def update(self, action, values):
        self._check_duplicate(
            values, excluded_action_id=action.ActionId
        )
        old_status = action.Status
        changes = []
        for field in EDITABLE_FIELDS:
            new_value = self._nullable_value(field, values[field])
            old_value = getattr(action, field)
            if old_value != new_value:
                changes.append((field, old_value, new_value))
                setattr(action, field, new_value)
        self._apply_completion_timestamp(action, old_status)
        for field, old_value, new_value in changes:
            self._record(
                action,
                "Field Changed",
                field_name=field,
                old_value=old_value,
                new_value=new_value,
            )
        self._commit_with_duplicate_guard()
        return action

    def update_status(self, action, status):
        if status not in ACTION_STATUSES:
            raise ValueError("Select a valid status.")
        old_status = action.Status
        if old_status == status:
            return action
        action.Status = status
        self._apply_completion_timestamp(action, old_status)
        self._record(
            action,
            "Status Changed",
            field_name="Status",
            old_value=old_status,
            new_value=status,
        )
        db.session.commit()
        return action

    def complete(self, action):
        return self.update_status(action, "Completed")

    def reopen(self, action):
        return self.update_status(action, "Open")

    def _check_duplicate(self, values, excluded_action_id=None):
        if self.repository.duplicate_exists(
            values["ThreatId"],
            values["ActionType"],
            values["Title"],
            excluded_action_id=excluded_action_id,
        ):
            raise DuplicateRemediationActionError(
                "An action with this threat, type, and title "
                "already exists."
            )

    @staticmethod
    def _assign(action, values):
        for field in EDITABLE_FIELDS:
            setattr(
                action,
                field,
                RemediationActionService._nullable_value(
                    field, values[field]
                ),
            )

    @staticmethod
    def _nullable_value(field, value):
        if field in {
            "Description",
            "Owner",
            "TicketReference",
            "Notes",
        }:
            return value or None
        return value

    @staticmethod
    def _apply_completion_timestamp(action, old_status):
        if action.Status == "Completed":
            if action.CompletedAt is None:
                action.CompletedAt = datetime.utcnow()
        elif old_status == "Completed" or action.CompletedAt is not None:
            action.CompletedAt = None

    @staticmethod
    def _record(
        action,
        change_type,
        *,
        field_name=None,
        old_value=None,
        new_value=None,
    ):
        db.session.add(
            RemediationActionHistory(
                ActionId=action.ActionId,
                ChangeType=change_type,
                FieldName=field_name,
                OldValue=(
                    None if old_value is None else str(old_value)
                ),
                NewValue=(
                    None if new_value is None else str(new_value)
                ),
            )
        )

    @staticmethod
    def _commit_with_duplicate_guard():
        try:
            db.session.commit()
        except IntegrityError as exc:
            db.session.rollback()
            raise DuplicateRemediationActionError(
                "An action with this threat, type, and title "
                "already exists."
            ) from exc
