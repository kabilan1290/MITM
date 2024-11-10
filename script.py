from mitmproxy import http, ctx,websocket
from urllib.parse import urlparse
import asyncio
import websockets
import re
from rich.syntax import Syntax

from rich import print
from rich.console import Console

console = Console()

class CORSchecker:
    def replay_with_different_origins(self, original_flow, origins):
        if "view" in ctx.master.addons:
            ctx.master.commands.call("view.flows.duplicate", [original_flow])

        for i, origin in enumerate(origins, start=1):
            # Copy the original flow for modification


            modified_flow = original_flow.copy()


            # Modify the origin in the request headers
            modified_flow.request.headers["Origin"] = origin

            # Replay the modified flow
            ctx.master.commands.call("replay.client", [modified_flow])

    def request(self, flow):
        # Add the evil.com origin to the request
        #flow.request.headers["Origin"] = "https://evil.com"

        # Check if the flow is a replay request
        if flow.is_replay:
            return
        parsed_url = urlparse(flow.request.url)
        hostname_vaue = parsed_url.hostname
        #domain = parsed_url.hostname.split('.')[1] + '.' + parsed_url.hostname.split('.')[2]
        cors1 = "https://evil.com"
        cors2 = "https://"+hostname_vaue+".evil.com"
        cors3 = "https://"+hostname_vaue+"evil.com"
        #cors4 = "https://"+"evil"+domain
        # enable cors4 somehow its throwing error
        cors5 = "null"
        # Define the list of different origins
        origins = [cors1, cors2, cors3, cors5] # i removed cors4 here

        # Replay the flow with different origins
        self.replay_with_different_origins(flow, origins)


    def response(self, flow: http.HTTPFlow) -> None:
        try:
            parsed_url = urlparse(flow.request.url)
            hostname_vaue = parsed_url.hostname
            # Check CORS-related issues in the response
            if "evil.com" in flow.response.headers["access-control-allow-origin"]:
                console.log("--------[+] CORS issue: Accept any domain--------",style="bold green")
                console.log("[+] Reflected Origin: " + flow.request.url,style="green")
                if "true" in flow.response.headers["access-control-allow-credentials"]:
                    console.log("[+] Credentials Enabled",style="red")
                    print("\n")
            if "https://"+hostname_vaue+".evil.com" in flow.response.headers["access-control-allow-origin"]:
                console.log("--------[+] CORS issue: CORS domain Bypass--------",style="bold green")
                console.log("[+] Reflected Origin: " + flow.request.url,style="green")
                if "true" in flow.response.headers["access-control-allow-credentials"]:
                    console.log("[+] Credentials Enabled",style="red")
                    print("\n")
            if "https://"+hostname_vaue+"evil.com" in flow.response.headers["access-control-allow-origin"]:
                console.log("--------[+] CORS issue: CORS Suffix Bypass--------",style="bold green")
                console.log("[+] Reflected Origin: " + flow.request.url,style="green")
                if "true" in flow.response.headers["access-control-allow-credentials"]:
                    console.log("[+] Credentials Enabled",style="red")
                    print("\n")
            if "https://"+"evil"+hostname_vaue in flow.response.headers["access-control-allow-origin"]:
                console.log("--------[+] CORS issue: CORS prefix Bypass--------",style="bold green")
                console.log("[+] Reflected Origin: " + flow.request.url,style="green")
                if "true" in flow.response.headers["access-control-allow-credentials"]:
                    console.log("[+] Credentials Enabled",style="red")
                    print("\n")
            if "null" in flow.response.headers["access-control-allow-origin"]:
                console.log("--------[+] CORS issue: CORS null Bypass--------",style="bold green")
                console.log("[+] Reflected Origin: " + flow.request.url,style="green")
                if "true" in flow.response.headers["access-control-allow-credentials"]:
                    console.log("[+] Credentials Enabled",style="red")
                    print("\n")                       
            else:
                pass
        except Exception as e:
            pass


class WebSocketChecker:
    def websocket_start(self, flow) -> None:
        if flow.websocket:
            # Determine the WebSocket scheme
            scheme = "wss" if flow.client_conn.tls_established else "ws"
            websocket_url = f"{scheme}://{flow.request.host}{flow.request.path}"
            console.log(f"[+] WebSocket connection detected: {websocket_url}",style="bold green")

            
            # Schedule the connection test as a background task
            asyncio.create_task(self.test_websocket_connection(websocket_url))

    async def test_websocket_connection(self, websocket_url: str):
        try:
            async with websockets.connect(websocket_url) as ws:
                console.log(f"[+] Successfully connected to WebSocket: {websocket_url}",style="green")
                message = await ws.recv()
                console.log(f"[+] Received message from WebSocket: {message}",style="green")
                print("\n")
        except Exception as e:
            console.log(f"[-] Failed to connect to WebSocket: {websocket_url}. Error: {e}",style="red")
            print("\n")


class PostMessageChecker:
    def response(self, flow: http.HTTPFlow) -> None:
        if flow.is_replay:
            return
        try:
            # Define the regular expression patterns
            postmessage_pattern = r'postMessage\([a-zA-Z]+,["\'].*?["\']\)'
            listener_pattern = r'window\.addEventListener\(["\']message["\'],\s*function\(e\)'
            location_search_pattern = r'.*\.location\.search|location\.search'
            hash_search_pattern = r'.*\.location\.hash|location\.hash'

            # Search for postMessage() pattern in the response text
            postmessage_matches = re.finditer(postmessage_pattern, flow.response.text)
            for match in postmessage_matches:
                # Extract surrounding text (5 lines before and 15 lines after)
                start_pos = max(0, match.start() - 200)
                end_pos = min(len(flow.response.text), match.end() + 600)
                context = flow.response.text[start_pos:end_pos]

                # Log the postMessage match context
                console.log("[+] postMessage call detected:", style="bold green")
                syntax = Syntax(context, "python", theme="monokai", line_numbers=True)
                console.print(flow.request.url)
                console.print(syntax)
                console.log("\n")

            # Search for window.addEventListener('message', function(e)) pattern in the response text
            listener_matches = re.finditer(listener_pattern, flow.response.text)
            for match in listener_matches:
                # Extract surrounding text (5 lines before and 15 lines after)
                start_pos = max(0, match.start() - 200)
                end_pos = min(len(flow.response.text), match.end() + 600)
                context = flow.response.text[start_pos:end_pos]

                # Log the addEventListener match context
                console.log("[+] window.addEventListener('message', function(e) detected:", style="bold green")
                syntax = Syntax(context, "python", theme="monokai", line_numbers=True)
                console.print(flow.request.url)
                console.print(syntax)
                console.log("\n")

            # Search for location.search pattern in the response text
            location_search_matches = re.finditer(location_search_pattern, flow.response.text)
            for match in location_search_matches:
                # Extract surrounding text (5 lines before and 15 lines after)
                start_pos = max(0, match.start() - 200)
                end_pos = min(len(flow.response.text), match.end() + 600)
                context = flow.response.text[start_pos:end_pos]

                # Log the location.search match context
                console.log("[+] location.search source detected:", style="bold green")
                syntax = Syntax(context, "javascript", theme="monokai", line_numbers=True)
                console.print(flow.request.url)
                console.print(syntax)
                console.log("\n")

            hash_search_matches = re.finditer(hash_search_pattern, flow.response.text)
            for match in hash_search_matches:
                # Extract surrounding text (5 lines before and 15 lines after)
                start_pos = max(0, match.start() - 200)
                end_pos = min(len(flow.response.text), match.end() + 600)
                context = flow.response.text[start_pos:end_pos]

                # Log the location.search match context
                console.log("[+] location.hash source detected:", style="bold green")
                syntax = Syntax(context, "javascript", theme="monokai", line_numbers=True)
                console.print(flow.request.url)
                console.print(syntax)
                console.log("\n")

        except Exception as e:
            pass

import re

class PostMessageChecker2:
    # Optimized combined regex pattern for all checks
    combined_pattern = re.compile(
        r'(?:postMessage\(\s*[a-zA-Z0-9_]+\s*,\s*["\']([^"\']+)["\']\s*\))|'  # postMessage pattern
        r'(?:window\.addEventListener\(\s*["\']message["\']\s*,)|'  # addEventListener pattern (simplified)
        r'(?:\blocation\.search\b)|'  # location.search pattern
        r'(?:\blocation\.hash\b)'  # location.hash pattern
    )

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.is_replay:
            return

        try:
            # Check and log any match from the combined pattern
            self.check_and_log(flow, self.combined_pattern)

        except Exception as e:
            pass

    def check_and_log(self, flow, pattern):
        """
        Helper function to search for a pattern and log the context if found.
        """
        for match in pattern.finditer(flow.response.text):
            # Determine which pattern matched and log accordingly
            if match.group(0).startswith("postMessage"):
                log_message = "[+] postMessage detected:"
            elif match.group(0).startswith("window.addEventListener"):
                log_message = "[+] window.addEventListener('message', ...) detected:"
            elif match.group(0).startswith("location.search"):
                log_message = "[+] location.search detected:"
            elif match.group(0).startswith("location.hash"):
                log_message = "[+] location.hash detected:"

            # Extract surrounding text (5 lines before and 15 lines after)
            start_pos = max(0, match.start() - 200)
            end_pos = min(len(flow.response.text), match.end() + 600)
            context = flow.response.text[start_pos:end_pos]

            # Limit the context length to avoid overloading the log
            context = context[:1000]  # Log the first 1000 characters of context

            # Log the match context with the corresponding pattern
            console.log(log_message, style="bold green")
            syntax = Syntax(context, "python", theme="monokai", line_numbers=True)
            console.print(flow.request.url)
            console.print(syntax)
            console.log("\n")


addons =[PostMessageChecker2()]
#addons = [CORSchecker(),WebSocketChecker(),PostMessageChecker()]