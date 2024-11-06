from mitmproxy import http, ctx
from urllib.parse import urlparse

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
        cors1 = "https://evil.com"
        cors2 = "https://"+hostname_vaue+".evil.com"
        cors3 = "https://"+hostname_vaue+"evil.com"
        cors4 = "https://"+"evil"+hostname_vaue
        cors5 = "null"
        # Define the list of different origins
        origins = [cors1, cors2, cors3, cors4, cors5]

        # Replay the flow with different origins
        self.replay_with_different_origins(flow, origins)


    def response(self, flow: http.HTTPFlow) -> None:
        try:
            parsed_url = urlparse(flow.request.url)
            hostname_vaue = parsed_url.hostname
            # Check CORS-related issues in the response
            if "evil.com" in flow.response.headers["access-control-allow-origin"]:
                print("--------[+] CORS issue: Accept any domain--------")
                print("[+] Reflected Origin: " + flow.request.url)
                if "true" in flow.response.headers["access-control-allow-credentials"]:
                    print("[+] Credentials Enabled")
                    print(flow.request.url)
            if "https://"+hostname_vaue+".evil.com" in flow.response.headers["access-control-allow-origin"]:
                print("--------[+] CORS issue: CORS domain Bypass--------")
                print("[+] Reflected Origin: " + flow.request.url)
                if "true" in flow.response.headers["access-control-allow-credentials"]:
                    print("[+] Credentials Enabled")
            if "https://"+hostname_vaue+"evil.com" in flow.response.headers["access-control-allow-origin"]:
                print("--------[+] CORS issue: CORS Suffix Bypass--------")
                print("[+] Reflected Origin: " + flow.request.url)
                if "true" in flow.response.headers["access-control-allow-credentials"]:
                    print("[+] Credentials Enabled")
            if "https://"+"evil"+hostname_vaue in flow.response.headers["access-control-allow-origin"]:
                print("--------[+] CORS issue: CORS prefix Bypass--------")
                print("[+] Reflected Origin: " + flow.request.url)
                if "true" in flow.response.headers["access-control-allow-credentials"]:
                    print("[+] Credentials Enabled")
            if "null" in flow.response.headers["access-control-allow-origin"]:
                print("--------[+] CORS issue: CORS null Bypass--------")
                print("[+] Reflected Origin: " + flow.request.url)
                if "true" in flow.response.headers["access-control-allow-credentials"]:
                    print("[+] Credentials Enabled")                       
            else:
                pass
        except Exception as e:
            pass

addons = [CORSchecker()]