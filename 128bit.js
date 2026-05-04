function generate128BitKey() {
    const bytes = new Uint8Array(16); // 16 bytes = 128 bits
    window.crypto.getRandomValues(bytes);

    return Array.from(bytes)
        .map(byte => byte.toString(16).padStart(2, "0"))
        .join("");
}

document.getElementById("generateBtn").addEventListener("click", function () {
    const key = generate128BitKey();
    document.getElementById("keyOutput").textContent = key;
});
