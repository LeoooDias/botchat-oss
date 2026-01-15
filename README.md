# botchat-oss - Public Transparency Code

This repository contains the core transparency code for botchat, enabling public auditability of our privacy-first architecture.

## What's Included

- **AI Provider Integrations** (`backend/app/providers/`)
  - Direct integrations with Anthropic, OpenAI, and Google Gemini
  - No data retention flags set, no training opt-ins

- **Authentication** (`backend/app/auth.py`)
  - Anonymous authentication model
  - OAuth ID hashing, no PII storage

- **Database Schema** (`backend/app/database.py`)
  - PostgreSQL schema showing what data is stored
  - Pseudonymous user model

- **Transparency Endpoint** (`backend/app/transparency.py`)
  - Public `/transparency` API endpoint
  - Read-only view with masked data

- **Message Handling** (`frontend/src/lib/components/ChatMessages.svelte`)
  - Client-side message rendering
  - localStorage-only storage (no server persistence)

## Purpose

This code is provided for transparency and auditability. The full application is developed in a private repository to protect intellectual property while maintaining accountability for our privacy commitments.

## License

Business Source License (BSL) - See LICENSE file
