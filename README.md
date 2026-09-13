# Homeschool tracker

A small family app: each child has their own page of weekly assignments (subjects × days), parents and kids check things off, and every assignment has a notes thread for questions and feedback.

- **Cloudflare Worker + D1** (SQLite). No build step: `worker.js` is the API, `public/index.html` is the whole app.
- **Logins:** name + PIN. Parents see every child and can edit; a child's login sees only their own page and can check off and leave notes.
- **First sign-in:** the "Parent" login with the PIN from the `ADMIN_PASSWORD` secret (`1234` if none was given). Change it under Family → Logins.

## Deploy
Push to `main`. The GitHub Actions workflow needs one repo secret, `CLOUDFLARE_API_TOKEN` (Workers Scripts: Edit, D1: Edit, Account Settings: Read). It creates the database, applies migrations, and deploys.

## Local
```
npx wrangler d1 migrations apply homeschool --local
npx wrangler dev
```
