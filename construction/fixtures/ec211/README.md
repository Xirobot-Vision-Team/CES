# EC-211 offline provider-shaped fixtures

These local JSON files are **synthetic only**; they are not captures of a live
GitHub or GitLab API, do not represent a real account, Issue, repository,
company, permission or production result, and are not remote credentials.
The test harness loads the independent repository + Issue objects into a fake
transport and never calls the network. The Issue titles/descriptions, numbers,
IDs and timestamps are invented. The application never serializes the raw
Issue title/body/labels in its returned projection.
