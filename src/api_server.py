# =========================================
# SafeMail-X AI API Server
# =========================================

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import List, Optional

import os
import json

# detection engines
from engines.hybrid_engine import hybrid_detect
from engines.url_analyzer import analyze_urls

# utilities
from utils.content_processor import build_full_email_text
from utils.evidence_builder import build_forensic_evidence
from utils.json_report import save_json_report
from utils.pdf_report import generate_pdf_report
from utils.image_downloader import download_images


# =========================================
# Path Setup
# =========================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(BASE_DIR, ".."))
REPORT_DIR = os.path.join(PROJECT_ROOT, "reports")

os.makedirs(REPORT_DIR, exist_ok=True)


# =========================================
# FastAPI App
# =========================================

app = FastAPI(
    title="SafeMail-X Phishing Detection API",
    version="4.2"
)

# Serve reports folder
app.mount("/reports", StaticFiles(directory=REPORT_DIR), name="reports")


# =========================================
# Enable CORS (for browser extension)
# =========================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================
# Request Schema
# =========================================

class EmailRequest(BaseModel):

    subject: str
    body: str

    sender: Optional[str] = ""
    links: Optional[List[str]] = []
    images: Optional[List[str]] = []


# =========================================
# Response Schema
# =========================================

class EmailResponse(BaseModel):

    final_label: str
    final_score: float

    ai_score: float
    rule_score: float

    rule_reasons: List[str]

    ai_reasons: Optional[List[str]] = []
    analysis_steps: Optional[List[str]] = []

    forensic_json: Optional[str] = None
    forensic_pdf: Optional[str] = None


# =========================================
# Health Check
# =========================================

@app.get("/")
def health_check():

    return {
        "status": "SafeMail-X AI Engine Running"
    }


# =========================================
# Scan Email Endpoint
# =========================================

@app.post("/scan-email", response_model=EmailResponse)
def scan_email(email: EmailRequest):

    try:

        # ---------------------------------
        # Combine Email Text + OCR Text
        # ---------------------------------

        print("\nDownloading images for OCR...")
        local_images = download_images(email.images) if email.images else []

        full_text = build_full_email_text(
            email.body,
            local_images
        )
        print("OCR extraction completed.")
        
        # Cleanup temp images
        for img_path in local_images:
            try:
                os.remove(img_path)
            except Exception as e:
                print("Failed to remove temp image:", e)

        # ---------------------------------
        # URL Analysis
        # ---------------------------------

        url_flags = []

        if email.links:
            url_flags = analyze_urls(email.links)

        # ---------------------------------
        # Hybrid AI + Rule Detection
        # ---------------------------------

        result = hybrid_detect(email.subject, full_text, email.sender if email.sender else "unknown_origin")

        # add URL flags to rule reasons
        if url_flags:
            result["rule_reasons"].extend(url_flags)

        # ---------------------------------
        # Build forensic evidence
        # ---------------------------------

        evidence = build_forensic_evidence(
            email.subject,
            full_text,
            result
        )

        # ---------------------------------
        # Save JSON forensic report
        # ---------------------------------

        json_path = save_json_report(evidence)

        json_filename = os.path.basename(json_path)
        report_id = json_filename.replace('.json', '')

        result["forensic_json"] = f"/reports/{json_filename}"
        result["forensic_pdf"] = f"/download-pdf/{report_id}"

        return result
        

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=f"Detection failed: {str(e)}"
        )
        


# =========================================
# Download Forensic PDF Endpoint
# =========================================

@app.get("/download-pdf/{report_id}")
def download_pdf(report_id: str):

    try:

        json_path = os.path.join(REPORT_DIR, f"{report_id}.json")

        if not os.path.exists(json_path):
            raise Exception("Specific Forensic JSON report could not be cryptographically physically located.")

        # load evidence
        with open(json_path) as f:
            evidence = json.load(f)

        # generate PDF
        pdf_path = generate_pdf_report(evidence)

        pdf_filename = os.path.basename(pdf_path)

        return {
            "pdf": f"/reports/{pdf_filename}"
        }

    except Exception as e:

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )