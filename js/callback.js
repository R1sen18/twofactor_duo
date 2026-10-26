// Hand the result back to core's /login/challenge/duo. The button is the no-JS fallback.
document.addEventListener('DOMContentLoaded', function () {
	var form = document.getElementById('twofactor-duo-form')
	if (form) {
		form.submit()
	}
})
