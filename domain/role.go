package domain

type RolePermissions struct {
	rolePermissions map[string][]string
}

func GetRolePermissions() RolePermissions {
	return RolePermissions{map[string][]string{
		"admin": {"GetAllCustomers", "GetCustomer", "NewAccount", "NewTransaction"},
		"user":  {"GetCustomer", "NewTransaction"},
	}}
}

func (rp RolePermissions) IsAuthorizedFor(role string, route string) bool {

	for _, r := range rp.rolePermissions[role] {
		if r == route {
			return true
		}

	}
	return false
}
