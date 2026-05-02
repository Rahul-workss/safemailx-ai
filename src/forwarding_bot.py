import time
import base64
import re
import os
from email.message import EmailMessage

from utils.gmail_fetcher import get_gmail_service
from utils.email_parser import parse_email
from engines.hybrid_engine import hybrid_detect
from engines.url_analyzer import analyze_urls
from engines.attachment_analyzer import analyze_attachments
from utils.evidence_builder import build_forensic_evidence
from utils.json_report import save_json_report
from utils.pdf_report import generate_pdf_report
from utils.image_downloader import download_images
from utils.content_processor import build_full_email_text
from utils.forwarding_parser import (
    extract_forwarded_payload,
    extract_original_headers,
    extract_original_sender,
)
from utils.url_extractor import extract_urls

def extract_forwarded_content(text):
    """
    Extracts the actual payload of a forwarded email.
    Strips the user's signature or "Fwd:" text from the top.
    """
    patterns = [
        r"---------- Forwarded message ---------",
        r"Begin forwarded message:",
        r"From:.*(.*)"
    ]
    
    for p in patterns:
        match = re.search(p, text, re.IGNORECASE)
        if match:
            # We cut off the top part and only scan the forwarded part
            return text[match.start():]
    
    # If no standard forward signature is found, just return all text
    return text


def send_reply_email(service, to_email, original_subject, final_label, final_score, pdf_path, attachment_findings=None):
    """
    Draft and send an HTML email with the scan result and PDF report.
    """
    reply_subject = f"SafeMail-X Report: {original_subject}"

    is_phishing = final_label.lower() == "phishing"

    # Color palette based on verdict
    if final_score >= 80:
        verdict_color = "#FF3B3B"
        verdict_bg    = "#2D0A0A"
        verdict_text  = "CRITICAL THREAT"
        meter_color   = "#FF3B3B"
        badge_label   = "PHISHING"
    elif final_score > 35:
        verdict_color = "#FF9F0A"
        verdict_bg    = "#2D1A00"
        verdict_text  = "SUSPICIOUS"
        meter_color   = "#FF9F0A"
        badge_label   = "SUSPICIOUS"
    else:
        verdict_color = "#30D158"
        verdict_bg    = "#0A2D12"
        verdict_text  = "LEGITIMATE"
        meter_color   = "#30D158"
        badge_label   = "SAFE"

    # Build attachment rows HTML
    att_rows_html = ""
    if attachment_findings:
        for f in attachment_findings:
            score_pct = int((f.get("threat_score") or 0) * 100)
            indicators = ", ".join(f["indicators"]) if f.get("indicators") else "CLEAN"
            row_color  = "#FF3B3B" if score_pct >= 50 else "#30D158"
            att_rows_html += f"""
            <tr>
                <td style="padding:10px 14px; color:#E0E0E0; font-size:13px; border-bottom:1px solid #2A2A2A;">{f['filename']}</td>
                <td style="padding:10px 14px; text-align:center; border-bottom:1px solid #2A2A2A;">
                    <span style="color:{row_color}; font-weight:700;">{score_pct}/100</span>
                </td>
                <td style="padding:10px 14px; color:#A0A0A0; font-size:12px; border-bottom:1px solid #2A2A2A;">{indicators}</td>
            </tr>"""

    att_section_html = ""
    if att_rows_html:
        att_section_html = f"""
        <div style="margin: 28px 0 0 0;">
            <p style="font-size:13px; font-weight:700; color:#888; letter-spacing:1.5px; text-transform:uppercase; margin:0 0 10px 0;">Attachment Analysis</p>
            <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse; border:1px solid #2A2A2A; border-radius:10px; overflow:hidden;">
                <thead>
                    <tr style="background:#1E1E1E;">
                        <th style="padding:10px 14px; color:#888; font-size:11px; text-align:left; font-weight:600; letter-spacing:1px; text-transform:uppercase;">File</th>
                        <th style="padding:10px 14px; color:#888; font-size:11px; text-align:center; font-weight:600; letter-spacing:1px; text-transform:uppercase;">Threat Score</th>
                        <th style="padding:10px 14px; color:#888; font-size:11px; text-align:left; font-weight:600; letter-spacing:1px; text-transform:uppercase;">Indicators</th>
                    </tr>
                </thead>
                <tbody>{att_rows_html}</tbody>
            </table>
        </div>"""

    html_body = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>SafeMail-X Report</title>
<style>
  @keyframes fillBar {{
    from {{ width: 0%; }}
    to   {{ width: {final_score}%; }}
  }}
  .threat-fill {{
    animation: fillBar 1.4s cubic-bezier(0.25, 1, 0.5, 1) forwards;
  }}
</style>
</head>
<body style="margin:0; padding:0; background:#0D0D0D; font-family:'Segoe UI', Arial, sans-serif;">

  <!-- Outer wrapper -->
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0D0D0D; padding: 32px 16px;">
    <tr><td align="center">

      <!-- Card -->
      <table width="600" cellpadding="0" cellspacing="0" style="background:#141414; border-radius:18px; overflow:hidden; border:1px solid #2A2A2A; max-width:600px;">

        <!-- Header Banner -->
        <tr>
          <td style="background:linear-gradient(135deg, #1A1A2E 0%, #16213E 50%, #0F3460 100%); padding:32px 36px; text-align:center;">
            <p style="margin:0; font-size:11px; font-weight:700; letter-spacing:3px; color:#4FC3F7; text-transform:uppercase; margin-bottom:10px;">SafeMail-X Analysis Report</p>
            <h1 style="margin:0; font-size:26px; font-weight:800; color:#FFFFFF; letter-spacing:-0.5px;">Security Scan Report</h1>
            <p style="margin:10px 0 0 0; font-size:13px; color:#88A0B0;">Your forwarded email has been fully analyzed.</p>
          </td>
        </tr>

        <!-- Verdict Banner -->
        <tr>
          <td style="background:{verdict_bg}; padding:22px 36px; text-align:center; border-bottom:2px solid {verdict_color};">
            <p style="margin:0; font-size:11px; font-weight:700; letter-spacing:3px; color:{verdict_color}; text-transform:uppercase; opacity:0.7; margin-bottom:6px;">Verdict</p>
            <h2 style="margin:0; font-size:30px; font-weight:900; color:{verdict_color}; letter-spacing:1px;">{verdict_text}</h2>
          </td>
        </tr>

        <!-- Main Content -->
        <tr>
          <td style="padding:32px 36px;">

            <!-- Threat Score Meter -->
            <p style="font-size:11px; font-weight:700; color:#888; letter-spacing:2px; text-transform:uppercase; margin:0 0 10px 0;">Threat Score</p>
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td>
                  <!-- Score number -->
                  <p style="margin:0 0 8px 0; font-size:42px; font-weight:900; color:{verdict_color}; line-height:1;">{final_score}<span style="font-size:18px; color:#555; font-weight:400;">/100</span></p>
                  <!-- Meter track -->
                  <div style="background:#2A2A2A; border-radius:10px; height:12px; width:100%; overflow:hidden;">
                    <!--[if mso]><v:rect xmlns:v="urn:schemas-microsoft-com:vml" style="width:{final_score}%;height:12px;" fillcolor="{meter_color}"><v:fill type="gradient"/></v:rect><![endif]-->
                    <div class="threat-fill" style="height:12px; width:{final_score}%; background:linear-gradient(90deg, {meter_color}88, {meter_color}); border-radius:10px;"></div>
                  </div>
                  <!-- Scale labels -->
                  <table width="100%" cellpadding="0" cellspacing="0" style="margin-top:6px;">
                    <tr>
                      <td style="font-size:10px; color:#444;">0</td>
                      <td style="font-size:10px; color:#444; text-align:center;">50</td>
                      <td style="font-size:10px; color:#444; text-align:right;">100</td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>

            <!-- Divider -->
            <div style="border-top:1px solid #2A2A2A; margin:28px 0;"></div>

            <!-- Status Pills Row -->
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td align="left">
                  <span style="display:inline-block; background:{verdict_bg}; color:{verdict_color}; border:1px solid {verdict_color}; border-radius:50px; padding:5px 16px; font-size:12px; font-weight:700; letter-spacing:1px;">{badge_label}</span>
                </td>
                <td align="right" style="color:#555; font-size:12px;">Generated by SafeMail-X</td>
              </tr>
            </table>

            {att_section_html}

            <!-- Divider -->
            <div style="border-top:1px solid #2A2A2A; margin:28px 0;"></div>

            <!-- Body Text -->
            <p style="font-size:14px; line-height:1.7; color:#A0A0A0; margin:0 0 8px 0;">
              A full <strong style="color:#E0E0E0;">Forensic PDF Report</strong> has been attached to this email. It contains a detailed breakdown of the triggered signals, including extracted URLs, sender analysis, and keyword pattern matches.
            </p>

          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="background:#0F0F0F; padding:20px 36px; text-align:center; border-top:1px solid #2A2A2A;">
            <p style="margin:0; font-size:12px; color:#333;">SafeMail-X Bot</p>
            <p style="margin:6px 0 0 0; font-size:11px; color:#2A2A2A;">The analysis has been completed and the report is attached.</p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>

</body>
</html>"""

    message = EmailMessage()
    message['To'] = to_email
    message['From'] = "me"
    message['Subject'] = reply_subject
    # Set plain-text fallback, then add the HTML version
    message.set_content(f"SafeMail-X Scan Complete\nVerdict: {badge_label}\nThreat Score: {final_score}/100\n\nSee the attached PDF for the full forensic report.")
    message.add_alternative(html_body, subtype='html')

    # Attach the generated PDF
    try:
        if os.path.exists(pdf_path):
            with open(pdf_path, 'rb') as f:
                pdf_data = f.read()
            message.add_attachment(
                pdf_data, 
                maintype='application', 
                subtype='pdf', 
                filename=os.path.basename(pdf_path)
            )
    except Exception as e:
        print(f"[ERROR] Could not attach PDF: {e}")

    raw_string = base64.urlsafe_b64encode(message.as_bytes()).decode()
    
    # Send the email using the Gmail API
    try:
        service.users().messages().send(userId='me', body={'raw': raw_string}).execute()
        print(f"[MAIL SENT] Reply sent to {to_email}")
    except Exception as e:
        print(f"[ERROR] Failed sending email: {e}")


def process_unread_messages():
    """
    Main polling logic.
    """
    service = get_gmail_service()
    
    print("[BOT] Checking for unread forwarded emails...")
    
    # Poll for unread messages only
    results = service.users().messages().list(userId='me', labelIds=['UNREAD'], q="").execute()
    messages = results.get('messages', [])

    if not messages:
        return

    print(f"[BOT] Found {len(messages)} unread messages.")

    for msg in messages:
        msg_id = msg['id']
        local_img_paths = []
        try:
            message_data = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
        
            # 1. Parse the email structure, including Base64 attachments
            parsed = parse_email(service, msg_id, message_data)
            
            # Sender of the forwarding email
            user_email = parsed.get("sender", "")
            subject    = parsed.get("subject", "Forwarded Scan Request")
            body_text  = parsed.get("body", "")
            images     = parsed.get("images", [])
            forwarder_headers = parsed.get("security_headers", {})
            
            print(f"\n[BOT] Processing msg={msg_id} from={user_email} subject='{str(subject)[:80]}'")
            
            # Only process emails that are explicitly forwarded to the bot
            subject_lower = str(subject).lower()
            if not subject_lower.startswith("fwd:") and not subject_lower.startswith("fw:"):
                print(f"[BOT] Ignoring non-forwarded personal/automated email: '{subject}'")
                # Mark it as read so we don't grab it again on the next loop
                service.users().messages().modify(
                    userId='me', id=msg_id, body={'removeLabelIds': ['UNREAD']}
                ).execute()
                continue
            
            # 2. Extract the forwarded payload
            target_text = extract_forwarded_payload(body_text)

            # Extract the original sender from the forwarded header block
            # Supports common forwarding formats across several languages
            original_sender = extract_original_sender(target_text)
            original_headers, auth_context = extract_original_headers(target_text)
            security_headers = original_headers if auth_context == "original_headers" else {}
            print(f"[BOT] Original sender={original_sender}; auth_context={auth_context}")

            if images:
                print(f"[BOT] Processing {len(images)} image(s) with OCR...")
                try:
                    # Save Base64 image data to local PNG files
                    local_img_paths = download_images(images)
                    
                    # Run OCR on the local image files and append the extracted text
                    target_text = build_full_email_text(target_text, local_img_paths)
                except Exception as e:
                    print(f"[OCR ERROR] Failed to run image analysis: {e}")

            # 3. Use URL Analyzer with sanitized, deduplicated URL records
            url_details = extract_urls(target_text)
            url_flags = analyze_urls(url_details) if url_details else []

            if url_flags:
                for detail in url_details:
                    flags = detail.setdefault("flags", [])
                    for flag in url_flags:
                        if flag not in flags:
                            flags.append(flag)
                    detail["safebrowsing_hit"] = any("SafeBrowsing" in f for f in url_flags)

            # 4. Attachment analysis
            # Run static inspection on common document attachments
            attachments = parsed.get("attachments", [])
            attachment_result = {"attachment_score": None, "attachment_findings": []}
            if attachments:
                print(f"[BOT] Analyzing {len(attachments)} file attachment(s)...")
                attachment_result = analyze_attachments(attachments)
                att_score = attachment_result.get("attachment_score")
                print(f"[BOT] Attachment aggregate threat score: {att_score}")

            # 5. Hybrid detection
            result = hybrid_detect(
                subject,
                target_text,
                original_sender,
                attachment_score=attachment_result.get("attachment_score"),
                url_flags=url_flags,
                security_headers=security_headers,
                auth_context=auth_context
            )

            # 6. Build Forensic Evidence
            evidence = build_forensic_evidence(
                subject,
                target_text,
                result,
                attachment_result=attachment_result,
                security_headers=security_headers,
                forwarder_headers=forwarder_headers,
                sender_raw=original_sender,
                forwarder_raw=user_email,
                url_details=url_details,
                auth_context=auth_context,
            )
            
            # 7. Save JSON + Generate PDF
            save_json_report(evidence)
            pdf_path = generate_pdf_report(evidence)

            print(f"[BOT] Analysis complete. Verdict: {result['final_label']} ({result['final_score']})")

            # 8. Reply to user
            if user_email:
                # We strip out the name to just get the plain email address if formatted like "Name <email>"
                email_addr_match = re.search(r'<(.*?)>', user_email)
                to_addr = email_addr_match.group(1) if email_addr_match else user_email
                
                send_reply_email(
                    service,
                    to_addr,
                    subject,
                    result['final_label'],
                    int(result['final_score'] * 100),
                    pdf_path,
                    attachment_findings=attachment_result.get("attachment_findings", [])
                )

            # 9. Move the processed email to Trash and mark it as read
            service.users().messages().trash(userId='me', id=msg_id).execute()
            service.users().messages().modify(
                userId='me', 
                id=msg_id, 
                body={'removeLabelIds': ['UNREAD']}
            ).execute()
            
            print(f"[BOT] Trashed and marked email {msg_id} as read.")

        except Exception as e:
            print(f"[CRITICAL ERROR] Failed processing msg {msg_id}. Error: {e}")
        finally:
            # Cleanup image attachments to prevent disk bloat even when analysis fails
            for img_path in local_img_paths:
                if os.path.exists(img_path):
                    try:
                        os.remove(img_path)
                    except Exception:
                        pass
            # Guarantee the email is marked as read so a bad payload never permanently bricks the polling loop
            try:
                service.users().messages().modify(userId='me', id=msg_id, body={'removeLabelIds': ['UNREAD']}).execute()
            except Exception:
                pass


def main():
    print("==============================================")
    print("SafeMail-X Email Forwarding Bot")
    print("==============================================")
    
    # We poll continuously
    while True:
        try:
            process_unread_messages()
        except KeyboardInterrupt:
            print("\n[BOT] Shutting down gracefully...")
            break
        except Exception as e:
            print(f"[NETWORK WARNING] Connection dropped or Google API timeout. Retrying in 10s... ({e})")
            
        time.sleep(10)


if __name__ == "__main__":
    main()
