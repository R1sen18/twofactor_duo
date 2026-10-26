<?php
/** @var array $_ */
/** @var \OCP\IL10N $l */
?>
<div class="body-login-container twofactor-duo">
	<form id="twofactor-duo-form" method="POST" action="<?php p($_['action']); ?>">
		<input type="hidden" name="challenge" value="duo">
		<p><?php p($l->t('Completing sign-in…')); ?></p>
		<button type="submit" class="primary"><?php p($l->t('Continue')); ?></button>
	</form>
</div>
