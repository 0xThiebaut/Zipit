import browser from "webextension-polyfill";
import ZipFile from "./zip";
import ZipCrypto from "./crypto";
import crc32 from "./crc";

let cache = new Map<string, Map<string, string>>();

interface CommandStatus {
    command_definition_id: string
    status: number
}

interface GetFileCommandStatus {
    command_definition_id: "getfile";
    status: 1;
    session_id: string;
    context: {
        download_token: string;
        download_file_name: string;
    };
    output: {
        download_token: string;
        download_file_name: string;
    };
}

// Create CRC_TABLE

function onBeforeCommandStatus(details: browser.WebRequest.OnBeforeRequestDetailsType): (void | browser.WebRequest.BlockingResponseOrPromise) {
    // Validate it is an expected GET request
    if (details.method !== "GET" || details.type !== "xmlhttprequest") {
        console.warn("Skipping unexpected " + details.url);
        return {};
    }
    // Validate the API version is V2
    const url = new URL(details.url);
    if (url.searchParams.get("useV2Api") !== "true" || url.searchParams.get("useV3Api") !== "false" || !url.searchParams.has("session_id")) {
        console.warn("Skipping incompatible " + details.url);
        return {};
    }
    // Set up a filter for the response
    const filter = browser.webRequest.filterResponseData(details.requestId);
    const data: ArrayBuffer[] = [];

    // Consume the response
    filter.ondata = async (event) => {
        data.push(event.data);
    }

    // Once done, extract the token, filename and update the filename to be a ZIP
    filter.onstop = async () => {
        // Decode the response
        const decoder = new TextDecoder("utf-8");
        let str = "";
        for (const buffer of data) {
            str += decoder.decode(buffer, {stream: true})
        }
        // Decode the JSON
        let response = JSON.parse(str) as CommandStatus

        if (response.command_definition_id === "getfile" && response.status === 1) {
            let status = response as GetFileCommandStatus

            // Ensure a map exists for the current session
            if (!cache.has(status.session_id)) {
                cache.set(status.session_id, new Map<string, string>())
            }

            // Update the download_token to download_file_name mapping
            cache.get(status.session_id)?.set(status.context.download_token, status.context.download_file_name)

            // Update the download_file_name to be a ZIP
            status.context.download_file_name = status.context.download_file_name + ".zip"
            status.output.download_file_name = status.output.download_file_name + ".zip"

            // Encode the JSON
            str = JSON.stringify(response)
        }

        // Encode the response
        const encoder = new TextEncoder()
        filter.write(encoder.encode(str))

        // Disconnect the filter
        filter.disconnect();
    }

    return {};
}

function onBeforeDownloadFile(details: browser.WebRequest.OnBeforeRequestDetailsType): (void | browser.WebRequest.BlockingResponseOrPromise) {
    // Validate it is an expected GET request
    if (details.method !== "GET" || details.type !== "xmlhttprequest") {
        console.warn("Skipping unexpected " + details.url);
        return {};
    }
    // Validate the API version is V2
    const url = new URL(details.url);
    const session_id = url.searchParams.get("session_id")
    const download_token = url.searchParams.get("token")
    if (url.searchParams.get("useV2Api") !== "true" || url.searchParams.get("useV3Api") !== "false" || !session_id || !download_token) {
        console.warn("Skipping incompatible " + details.url);
        return {};
    }

    const name = cache.get(session_id)?.get(download_token)
    if (!name) {
        console.error("Skipping untracked name for session " + session_id + " with token " + download_token);
        return {}
    }

    // Set up a filter for the response
    const filter = browser.webRequest.filterResponseData(details.requestId);

    const password = new Uint8Array("infected".split('').map(c => c.charCodeAt(0)))

    let chunks: Uint8Array[] = [];
    let size = 0;
    let crc = -1;
    const encryptor = new ZipCrypto(password)

    // Consume the response
    filter.ondata = (event) => {
        const bytes = new Uint8Array(event.data)
        // Update the data size
        size += bytes.byteLength
        // Compute the crc32
        bytes.forEach(b => {
            crc = crc32(crc, b)
        })
        // Encrypt the chunk
        chunks.push(encryptor.encrypt(bytes))
    }

    // Once done, extract the token, filename and update the filename to be a ZIP
    filter.onstop = async () => {
        // Create a new ZipFile
        crc = (-1 ^ crc) >>> 0
        const file = new ZipFile(filter, name, size, crc, password)
        // Create a new decryptor for the chunks
        const decryptor = new ZipCrypto(password)
        // Decrypt and write each chunk
        for (const chunk of chunks) {
            file.write(decryptor.decrypt(chunk))
        }
        // Finalize the ZIP file
        file.finalize()
        // Disconnect the filter
        filter.disconnect();
    }

    return {};
}

browser.webRequest.onBeforeRequest.addListener(
    onBeforeCommandStatus,
    {urls: ["https://security.microsoft.com/apiproxy/mtp/automatedIr/v2/live_response/commands/*"]},
    ["blocking"]
);

browser.webRequest.onBeforeRequest.addListener(
    onBeforeDownloadFile,
    {urls: ["https://security.microsoft.com/apiproxy/mtp/automatedIr/v2/live_response/download_file?*"]},
    ["blocking"]
);