set -eu

export HOWL_CONTROL_DATABASE_URL
HOWL_CONTROL_DATABASE_URL="postgresql://$HOWL_BETA_DB_ROLE:$(cat /run/howl/database-password)@127.0.0.1:5432/$HOWL_BETA_DB"
if [ "$#" -eq 0 ]; then
    export HOWL_CONTROL_STATE_KEY HOWL_CONTROL_AUDIENCE
    HOWL_CONTROL_STATE_KEY=$(cat /run/howl/state-key)
    HOWL_CONTROL_AUDIENCE=$(cat /run/howl/audience)
    if [ "${HOWL_BETA_GITHUB_FILES:-0}" = 1 ]; then
        export HOWL_GITHUB_CLIENT_ID HOWL_GITHUB_CLIENT_SECRET
        HOWL_GITHUB_CLIENT_ID=$(cat /run/secrets/github-client-id)
        HOWL_GITHUB_CLIENT_SECRET=$(cat /run/secrets/github-client-secret)
    fi
fi
exec /opt/howl/howl-control-plane "$@"
