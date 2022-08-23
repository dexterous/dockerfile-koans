package main
import future.keywords.in

# Find USER lines
find_users(x, idx) {
    contains(x.Cmd, "user")
    idx
}

# Find USER lines with root
find_roots(x, idx) {
    contains(x.Cmd, "user")
    contains(x.Value[0], "root")
    idx
}

suspicious_env_keys = [
    "passwd",
    "password",
    "secret",
    "key",
    "access",
    "api_key",
    "apikey",
    "token",
]

pkg_update_commands = [
    "apk upgrade",
    "apt-get upgrade",
    "dist-upgrade",
]

image_tag_list = [
    "latest",
    "LATEST",
]

# Looking for latest docker image used
deny[msg] {
    input[i].Cmd == "from"
    val := split(input[i].Value[0], ":")
    count(val) == 1
    msg = sprintf("Do not use latest tag with image: %s", [val])
}

# Looking for latest docker image used
deny[msg] {
    input[i].Cmd == "from"
    val := split(input[i].Value[0], ":")
    contains(val[1], image_tag_list[_])
    msg = sprintf("Do not use latest tag with image: %s", [input[i].Value])
}

# Looking for apk upgrade command used in Dockerfile
deny[msg] {
    input[i].Cmd == "run"
    val := concat(" ", input[i].Value)
    contains(val, pkg_update_commands[_])
    msg = sprintf("Do not use upgrade commands: %s", [val])
}

# Looking for ADD command instead using COPY command
deny[msg] {
    input[i].Cmd == "add"
    val := concat(" ", input[i].Value)
    msg = sprintf("Use COPY instead of ADD: %s", [val])
}

# Correct usage of expose
deny[msg] {
    some "127.0.0.1" in input[i].Value
    msg = sprintf("Use of 127.0.0.1 in a dockerfile intended for kubernetes %s", [input[i].Value])
}

# The final USER line must not be root
deny[msg] {      
    userLines := {i | input[i]; find_users(input[i], i)}
    rootLines := {i | input[i]; find_roots(input[i], i)}
    max(userLines) == max(rootLines)
    msg = sprintf("%s", ["Use of root in final USER line is not permitted"])
}

# sudo usage
deny[msg] {
    input[i].Cmd == "run"
    val := concat(" ", input[i].Value)
    contains(lower(val), "sudo")
    msg = sprintf("Avoid using 'sudo' command: %s", [val])
}

# No Healthcheck usage
deny[msg] {
    input[i].Cmd == "healthcheck"
    msg := "no healthcheck"
}

# Missing layers
# some "as" in input[i].Value 
deny[msg] {
    input[i].Cmd == "from"
    val = input[i]
    "as" in val.Value[j]
    msg = sprintf("ASDF: %s", ["layer must have a name"])
}
