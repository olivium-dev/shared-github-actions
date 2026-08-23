# shared-github-actions

The operational Jeeb reusable workflow accepts reviewed `seedData` from the
caller deployment JSON. `scripts/operational_seed.py` validates the editable
users and wallets, binds their digest and counts into the deployment lock, and
generates SQL only for the lease-local User and Wallet databases. Activation
requires the seeded roster, regular/Jeeber super-login, and Jeeber wallet
balance to pass through the real gateway.

The protected `super_login_passcode` workflow secret is carried only in memory
to the lease and overrides the copied staging value for user-management. This
keeps the ephemeral CMS login aligned without modifying staging or production.
