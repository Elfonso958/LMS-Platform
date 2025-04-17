from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from datetime import datetime
import os
from app.models import db, DocumentType, DocumentReviewRequest, User
from app.forms import DocumentTypeForm, FormUpload, DirectDocumentUploadForm
from app.email_utils import send_email
from app.utils import admin_required

from werkzeug.utils import secure_filename
from sqlalchemy.orm import aliased
from collections import defaultdict


document_bp = Blueprint("document", __name__)


@document_bp.route('/document_types', methods=['GET', 'POST'])
@login_required
def manage_document_types():
    form = DocumentTypeForm()
    if form.validate_on_submit():
        new_type = DocumentType(name=form.name.data.strip())
        db.session.add(new_type)
        db.session.commit()
        flash('Document type added.', 'success')
        return redirect(url_for('document.manage_document_types'))

    document_types = DocumentType.query.order_by(DocumentType.name.asc()).all()
    return render_template("documents/manage_document_types.html", form=form, document_types=document_types)


@document_bp.route('/document_types/<int:id>/update', methods=['POST'])
@login_required
def update_document_type(id):
    doc_type = DocumentType.query.get_or_404(id)
    doc_type.name = request.form['name'].strip()
    db.session.commit()
    flash('Document type updated.', 'success')
    return redirect(url_for('document.manage_document_types'))


@document_bp.route('/document_types/<int:id>/delete')
@login_required
def delete_document_type(id):
    doc_type = DocumentType.query.get_or_404(id)
    db.session.delete(doc_type)
    db.session.commit()
    flash('Document type deleted.', 'warning')
    return redirect(url_for('document.manage_document_types'))


@document_bp.route("/user_documents")
@login_required
def user_documents():
    selected_id = request.args.get('selected', type=int)

    doc_alias = aliased(DocumentReviewRequest)
    users_with_docs = (
        db.session.query(User)
        .join(doc_alias, User.id == doc_alias.user_id)
        .filter(doc_alias.status == 'approve')
        .distinct()
        .all()
    )

    grouped_docs = {}
    for user in users_with_docs:
        docs = DocumentReviewRequest.query.filter_by(
            user_id=user.id, status='approve'
        ).order_by(DocumentReviewRequest.submitted_at.desc()).all()

        doc_groups = defaultdict(list)
        for doc in docs:
            doc_groups[doc.type.name if doc.type else "Other"].append(doc)

        grouped_docs[user.id] = {
            "user": user,
            "documents": doc_groups
        }

    document_types = DocumentType.query.order_by(DocumentType.name).all()

    return render_template(
        "documents/user_documents.html",
        grouped_docs=grouped_docs,
        selected_id=selected_id,
        document_types=document_types
    )


@document_bp.route("/upload_document_admin", methods=["POST"])
@login_required
def upload_document_admin():
    file = request.files.get("file")
    document_type_id = request.form.get("document_type_id")
    expiry_date = request.form.get("document_expiry_date")
    user_id = request.form.get("user_id")

    if not all([file, document_type_id, expiry_date, user_id]):
        flash("Missing fields for document upload.", "danger")
        return redirect(url_for("document.user_documents"))

    user = User.query.get(user_id)
    document_type = DocumentType.query.get(document_type_id)

    if not user or not document_type:
        flash("Invalid user or document type.", "danger")
        return redirect(url_for("document.user_documents"))

    doc_type_name = secure_filename(document_type.name)
    username = secure_filename(user.username)
    formatted_date = datetime.strptime(expiry_date, "%Y-%m-%d").strftime("%Y-%m-%d")

    extension = os.path.splitext(file.filename)[1]
    renamed_filename = secure_filename(f"{doc_type_name} - {user.username} - {formatted_date}{extension}")

    upload_folder = os.path.join(current_app.static_folder, 'uploads', user.username, doc_type_name)
    os.makedirs(upload_folder, exist_ok=True)

    full_path = os.path.join(upload_folder, renamed_filename)
    file.save(full_path)

    relative_path = f"uploads/{user.username}/{doc_type_name}/{renamed_filename}"

    new_doc = DocumentReviewRequest(
        user_id=user.id,
        document_type_id=document_type.id,
        document_expiry_date=formatted_date,
        file_path=relative_path,
        submitted_at=datetime.utcnow(),
        status='approve'
    )
    db.session.add(new_doc)
    db.session.commit()

    flash(f"{document_type.name} uploaded for {user.username}.", "success")
    return redirect(url_for("document.user_documents"))

@document_bp.route("/review_documents", methods=["GET", "POST"])
@login_required
def review_documents():
    page = request.args.get("page", 1, type=int)
    filter_type = request.args.get("filter", "", type=str)

    if request.method == "POST":
        doc_id = request.form.get("doc_id")
        new_status = request.form.get("action")
        comment = request.form.get("comment", "")

        if not doc_id or not new_status:
            flash("Missing document ID or action.", "danger")
            return redirect(url_for("document.review_documents", page=page, filter=filter_type))

        doc = DocumentReviewRequest.query.get(doc_id)
        if not doc:
            flash("Document not found.", "danger")
            return redirect(url_for("document.review_documents", page=page, filter=filter_type))

        doc.status = new_status
        doc.review_comment = comment
        doc.reviewed_by_id = current_user.id
        doc.reviewed_at = datetime.utcnow()

        # Delete file if rejected
        if new_status == 'reject':
            if doc.file_path:
                full_path = (
                    doc.file_path
                    if os.path.isabs(doc.file_path)
                    else os.path.join(current_app.static_folder, doc.file_path.lstrip("/"))
                )
                if os.path.exists(full_path):
                    try:
                        os.remove(full_path)
                    except Exception:
                        pass

            # ✅ Send rejection email
            if doc.user.email:
                email_body = render_template(
                    "emails/document_rejection_notice.html",
                    user=doc.user,
                    document=doc,
                    upload_url=url_for("document.upload_document", _external=True)
                )
                send_email(
                    subject=f"Document Rejected: {doc.type.name}",
                    recipients=[doc.user.email],
                    html=email_body
                )

        # Update medical expiry if approved
        if new_status == 'approved' and doc.type and doc.type.name.lower() == "medical":
            doc.user.medical_expiry = doc.document_expiry_date

        db.session.commit()
        flash(f"Document {new_status.capitalize()}!", "success")
        return redirect(url_for("document.review_documents", page=page, filter=filter_type))

    # GET request
    document_types = DocumentType.query.order_by(DocumentType.name.asc()).all()
    query = DocumentReviewRequest.query.filter_by(status="pending")

    if filter_type:
        matched_type = DocumentType.query.filter_by(name=filter_type).first()
        if matched_type:
            query = query.filter_by(document_type_id=matched_type.id)

    pending_docs = query.order_by(DocumentReviewRequest.submitted_at.desc()).paginate(page=page, per_page=10)

    return render_template(
        "documents/review_documents.html",
        pending_docs=pending_docs,
        document_types=document_types,
        filter=filter_type
    )

########################
###DOCUMENT UPLOAD###
#######################
@document_bp.route('/upload_document', methods=['GET', 'POST'])
@login_required
def upload_document():
    form = FormUpload()

    # Populate dropdown from DB
    form.document_type.choices = [(dt.id, dt.name) for dt in DocumentType.query.order_by(DocumentType.name).all()]

    if form.validate_on_submit():
        file = form.file.data
        document_type_id = form.document_type.data
        expiry_date = form.document_expiry_date.data

        # Get document type name
        document_type = DocumentType.query.get(document_type_id)
        doc_type_name = secure_filename(document_type.name)
        username = secure_filename(current_user.username)
        formatted_date = expiry_date.strftime('%Y-%m-%d')

        # Filename: e.g., "Medical - Jayden Beck - 2025-08-01.pdf"
        extension = os.path.splitext(file.filename)[1]
        renamed_filename = secure_filename(f"{doc_type_name} - {current_user.username} - {formatted_date}{extension}")

        # Folder structure: static/uploads/<Username>/<DocumentType>
        upload_folder = os.path.join(current_app.static_folder, 'uploads', current_user.username, doc_type_name)
        os.makedirs(upload_folder, exist_ok=True)

        # Save path
        full_path = os.path.join(upload_folder, renamed_filename)
        file.save(full_path)

        # Relative path for DB and static serving
        relative_path = f"uploads/{current_user.username}/{doc_type_name}/{renamed_filename}"

        # Save metadata to DB
        new_request = DocumentReviewRequest(
            user_id=current_user.id,
            document_type_id=document_type_id,
            document_expiry_date=expiry_date,
            file_path=relative_path,
            submitted_at=datetime.utcnow(),
            status='pending'
        )
        db.session.add(new_request)
        db.session.commit()

        flash("Your document has been submitted for review.", "success")
        return redirect(url_for('document.upload_document'))

    return render_template("documents/upload_document.html", form=form)
