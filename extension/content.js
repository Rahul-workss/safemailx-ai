async function scanEmail() {

    // Extract email text
    let emailBody = document.body.innerText;

    let subject = document.title;

    let payload = {
        subject: subject,
        body: emailBody,
        images: []
    };

    try {

        let response = await fetch("http://127.0.0.1:8000/scan-email", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });

        let result = await response.json();

        showWarning(result);

    } catch (err) {

        console.log("SafeMail-X API not reachable");

    }
}


function showWarning(result) {

    let banner = document.createElement("div");

    banner.style.position = "fixed";
    banner.style.top = "0";
    banner.style.left = "0";
    banner.style.width = "100%";
    banner.style.padding = "10px";
    banner.style.background = "red";
    banner.style.color = "white";
    banner.style.fontSize = "16px";
    banner.style.zIndex = "9999";

    banner.innerText =
        "SafeMail-X: " +
        result.final_label +
        " | Score: " +
        result.final_score;

    document.body.prepend(banner);
}


// Run scanner after page loads
setTimeout(scanEmail, 5000);