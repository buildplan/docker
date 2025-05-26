from flask import Flask, request, jsonify
import requests
import json
import os
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO)

# Get ntfy configuration from environment variables
NTFY_SERVER_URL = os.environ.get('NTFY_SERVER_URL') # e.g., https://ntfy.alisufyan.cloud
NTFY_TOPIC = os.environ.get('NTFY_TOPIC')           # e.g., my_registry
NTFY_ACCESS_TOKEN = os.environ.get('NTFY_ACCESS_TOKEN')
NTFY_PRIORITY = os.environ.get('NTFY_PRIORITY', 'default') # Eg: high, max, low, min

@app.route('/notify', methods=['POST'])
def registry_notification_handler():
    if not NTFY_SERVER_URL or not NTFY_TOPIC:
        app.logger.error("NTFY_SERVER_URL or NTFY_TOPIC not configured.")
        return jsonify({"status": "error", "message": "Receiver not configured"}), 500

    if not request.is_json:
        app.logger.warning("Received non-JSON request")
        return jsonify({"status": "error", "message": "Request was not JSON"}), 400

    data = request.get_json()
    app.logger.info(f"Received registry webhook: {json.dumps(data, indent=2)}")

    if data.get('events'):
        for event in data['events']:
            action = event.get('action')
            target = event.get('target', {})
            repository = target.get('repository')
            tag = target.get('tag')
            actor_name = event.get('actor', {}).get('name')
            digest = target.get('digest')
            manifest_url = target.get('url')


            if action == 'push' and repository: # Tag might be empty for manifest lists
                # Construct a more detailed or simpler message as you prefer
                title = f"Image Pushed: {repository}"
                if tag:
                    title += f":{tag}"

                message_lines = []
                if tag:
                    message_lines.append(f"Tag: {tag}")
                message_lines.append(f"Repository: {repository}")
                if actor_name:
                    message_lines.append(f"Pushed by: {actor_name}")
                if digest:
                    message_lines.append(f"Digest: {digest[:12]}...") # Shorten digest for readability

                # Create a clickable link if manifest URL is available
                # Note: This URL might point to the manifest within the registry's internal API
                # and may not be directly browser-accessible without auth.
                click_action = None
                if manifest_url:
                     click_action = f"view, {manifest_url}, Open Manifest URL"


                full_message = "\n".join(message_lines)
                app.logger.info(f"Processing notification for ntfy: Title='{title}', Message='{full_message}'")

                headers = {
                    "Title": title.encode('utf-8'), # ntfy expects headers to be strings
                    "Priority": NTFY_PRIORITY
                }
                if NTFY_ACCESS_TOKEN:
                    headers["Authorization"] = f"Bearer {NTFY_ACCESS_TOKEN}"
                if click_action:
                    headers["Click"] = click_action

                try:
                    response = requests.post(
                        f"{NTFY_SERVER_URL.rstrip('/')}/{NTFY_TOPIC}",
                        data=full_message.encode('utf-8'), # Send message as plain text
                        headers=headers
                    )
                    response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
                    app.logger.info(f"Notification sent to ntfy. Status: {response.status_code}")
                except requests.exceptions.RequestException as e:
                    app.logger.error(f"Error sending notification to ntfy: {e}")
                    if hasattr(e, 'response') and e.response is not None:
                        app.logger.error(f"ntfy response content: {e.response.text}")

    return jsonify({"status": "success"}), 200

if __name__ == '__main__':
    if not NTFY_SERVER_URL or not NTFY_TOPIC:
        app.logger.error("FATAL: NTFY_SERVER_URL or NTFY_TOPIC environment variables are not set.")
        exit(1)

    app.logger.info(f"Webhook receiver starting. Notifications will be sent to: {NTFY_SERVER_URL.rstrip('/')}/{NTFY_TOPIC}")
    app.run(host='0.0.0.0', port=5001, debug=False)
