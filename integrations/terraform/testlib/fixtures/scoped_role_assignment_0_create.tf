resource "teleport_scoped_role_assignment" "test" {
  version = "v1"
  metadata = {
    name = "test-scoped-role-assignment"
  }
  scope = "/staging"
  spec = {
    user = "testuser"
    assignments = [{
      role  = "test-scoped-role"
      scope = "/staging/aa"
    }]
  }
}
