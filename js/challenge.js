// Send the browser on to Duo's Universal Prompt. The visible link is the no-JS fallback.
document.addEventListener('DOMContentLoaded', function () {
	var link = document.getElementById('twofactor-duo-link')
	if (link && link.href) {
		window.location.href = link.href
	}
})
