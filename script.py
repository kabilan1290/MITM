from mitmproxy import http, ctx

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
        cors1 = "https://evil.com"
        cors2 = flow.request.url[:-1]+".evil.com"
        cors3 = flow.request.url[:-1]+"evil.com"
        cors4 = "evil"+flow.request.url[:-1]
        cors5 = "null"
        # Define the list of different origins
        origins = [cors1, cors2, cors3, cors4, cors5]

        # Replay the flow with different origins
        self.replay_with_different_origins(flow, origins)


    def response(self, flow: http.HTTPFlow) -> None:
        try:
            # Check CORS-related issues in the response
            if "https://evil.com" in flow.response.headers["access-control-allow-origin"]:
                print("--------[+] CORS issue: Accept any domain--------")
                print("[+] Reflected Origin: " + flow.request.url)
                if "true" in flow.response.headers["access-control-allow-credentials"]:
                    print("[+] Credentials Enabled")
                    print(flow.request.url)
            if flow.request.url in flow.response.headers["access-control-allow-origin"]:
                print("--------[+] CORS issue: CORSdomain Bypass--------")
                print("[+] Reflected Origin: " + flow.request.url)
                if "true" in flow.response.headers["access-control-allow-credentials"]:
                    print("[+] Credentials Enabled")
            else:
                print("--------[-] No CORS issue--------")
        except Exception as e:
            print(f"Error processing response: {e}")

addons = [CORSchecker()]