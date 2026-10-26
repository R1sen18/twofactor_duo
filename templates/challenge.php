<?php
/** @var array $_ */
/** @var \OCP\IL10N $l */
?>
<div class="body-login-container twofactor-duo">
<?php if (!empty($_['error'])): ?>
	<p class="warning"><?php p($_['error']); ?></p>
<?php else: ?>
	<p><?php p($l->t('Redirecting to Duo Security…')); ?></p>
	<p><a id="twofactor-duo-link" class="button primary" href="<?php p($_['duo_url']); ?>"><?php p($l->t('Continue to Duo Security')); ?></a></p>
<?php endif; ?>
</div>
