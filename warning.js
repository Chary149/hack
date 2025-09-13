(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const threatParam = urlParams.get('threat');
    if (threatParam) {
        const threat = JSON.parse(decodeURIComponent(threatParam));
        document.getElementById('threat-details').textContent = `Threat: ${threat.threat_type} at ${threat.url}`;
        if (threat.isRedirect) {
            document.getElementById('redirect-info').textContent = 'This site was accessed via a redirect from another page.';
        }

        document.getElementById('proceed').addEventListener('click', () => {
            // Allow proceeding to the original URL
            window.location.href = threat.url;
        });

        document.getElementById('go-back').addEventListener('click', () => {
            window.history.back();
        });
    }
})();
