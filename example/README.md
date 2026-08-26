# `rakomi_flutter_example`

Minimal Flutter app demonstrating the SDK. Single screen with
`RakomiProvider` + `RakomiAuthGate` + `RakomiSignInForm` + `RakomiUserAvatar`.

## Run

```bash
cd example
flutter pub get
flutter run -d chrome           # Web
flutter run -d "iPhone 16"       # iOS simulator
flutter run -d emulator-5554     # Android emulator
```

## Production mode

Set `RAKOMI_PUBLISHABLE_KEY` and `RAKOMI_API_BASE_URL` to your tenant config.
Sign in normally via the form.

```bash
RAKOMI_PUBLISHABLE_KEY=pk_live_… \
RAKOMI_API_BASE_URL=https://api.rakomi.com \
flutter run
```

## Local development

Point the demo at a locally running API:

```bash
RAKOMI_API_BASE_URL=http://localhost:3001 \
RAKOMI_PUBLISHABLE_KEY=pk_test_… \
flutter run -d chrome
```

The demo signs in through the ordinary end-user flow. It has no privileged
bootstrap path, and it never calls an impersonation endpoint.

## With Riverpod

See sibling demo at `example/with_riverpod/` for the recipe of consuming
`RakomiAuth.instance.authStateChanges` via `ConsumerWidget`. NON-NORMATIVE —
example code only; the SDK does NOT depend on Riverpod.
