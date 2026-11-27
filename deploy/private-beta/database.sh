set -euo pipefail

directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
private=${HOWL_BETA_PRIVATE_DIR:?Set HOWL_BETA_PRIVATE_DIR to the private credentials directory}
[[ "$private" = /* ]]

compose() {
    docker compose -f "$directory/compose.yaml" "$@"
}

postgres() {
    compose exec -T postgres "$@"
}

sql() {
    postgres psql --no-psqlrc --no-password --username=postgres --set=ON_ERROR_STOP=1 "$@"
}

password() {
    local role=$1 file=$2 value
    value=$(<"$private/$file")
    if [[ ! "$value" =~ ^[a-f0-9]{64}$ ]]; then
        printf '%s\n' "Invalid PostgreSQL credential file: $file" >&2
        return 1
    fi
    printf '%s\n%s\n' "$value" "$value" |
        sql --quiet --dbname=howl --command="\\password $role"
}

database() {
    if [[ ! "$1" =~ ^howl(_[a-z0-9]+)*$ ]]; then
        printf '%s\n' 'Use a database name beginning with howl.' >&2
        return 1
    fi
}

restrict_database() {
    sql --quiet --dbname="$1" --set="target=$1" <<'SQL'
REVOKE CONNECT, TEMPORARY ON DATABASE :"target" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"target" TO howl_control_runtime;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SQL
}

case "${1:-}" in
    bootstrap)
        [[ $# = 1 ]]
        sql --quiet --dbname=howl <<'SQL'
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'howl_control_owner') THEN
        CREATE ROLE howl_control_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'howl_control_runtime') THEN
        CREATE ROLE howl_control_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
    END IF;
END
$$;
ALTER DATABASE howl OWNER TO howl_control_owner;
SQL
        restrict_database howl
        password howl_control_owner postgres-owner
        password howl_control_runtime postgres-runtime
        ;;
    dump)
        [[ $# = 2 ]]
        database "$2"
        postgres pg_dump --format=custom --no-password --username=postgres --dbname="$2"
        ;;
    restore)
        [[ $# = 2 ]]
        database "$2"
        postgres createdb --no-password --username=postgres --owner=howl_control_owner --template=template0 "$2" </dev/null
        restrict_database "$2"
        postgres pg_restore --exit-on-error --single-transaction --no-password --username=postgres --dbname="$2"
        ;;
    *)
        printf '%s\n' 'Usage: bash database.sh bootstrap | dump DATABASE | restore NEW_DATABASE' >&2
        exit 2
        ;;
esac
