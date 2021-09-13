package rbac

default allow = false

# Policy id        7c7948f4-f4f6-40f0-97a7-84474fea1e35
# Name             rbac-testing-policy
# Integration      MyFirstPolicy
# Tenant           2870e01d-4150-4339-828c-48524ef1ed89
# Last update      09/13/2021 11:44:24 +00:00

# Custom block
allow {
    ds := data.datasources["rbac-testing-datasource"]
    permissions[ds.users[input.user].role][_] == input.action
}

role_graph[role] = includes {
    ds := data.datasources["rbac-testing-datasource"]
    ds.roles[role]
    includes := { include | include := ds.roles[role].includes[_] }
}

permissions[role] = permissions {
    ds := data.datasources["rbac-testing-datasource"]
    ds.roles[role]
    includes := graph.reachable(role_graph, {role})
    permissions := { perm | includes[i]; perm := ds.roles[i].permissions[_] }
}

