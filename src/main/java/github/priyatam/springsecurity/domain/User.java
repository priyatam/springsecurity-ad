package github.priyatam.springsecurity.domain;

import javax.management.relation.Role;
import javax.persistence.*;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

@Entity
@NamedQueries({
        @NamedQuery(name = "User.FIND_BY_USERNAME", query = "select o from User o where o.username = :username")
})
@NamedQuery(name = "User.FIND_BY_USERNAME", query = "select o from User o where o.username = :username")
public class User implements Serializable {
    static final private long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(updatable = false, nullable = false)
    private Long id;

    private String password;

    private String username;

    @ManyToMany(cascade = {CascadeType.MERGE, CascadeType.REFRESH}, fetch = FetchType.EAGER)
    private List<Role> roles = new ArrayList<Role>();
    
    public User(String password, String userName) {
        super();
        this.password = password;
        this.username = userName;
    }

    public Long getId() {
        return id;
    }

    public String getPassword() {
        return password;
    }

    public String getUsername() {
        return username;
    }

    public List<Role> getRoles() {
        return roles;
    }

    /**
     * Returns the granted authorities for this user. You may override this
     * method to provide your own custom authorities.
     */
    @Transient
    public List<String> getRoleNames() {
        List<String> roleNames = new ArrayList<String>();

        for (Role role : getRoles()) {
            roleNames.add(role.getRoleName());
        }

        return roleNames;
    }

    public boolean addRole(Role role) {
        return getRoles().add(role);
    }

    public boolean removeRole(Role role) {
        return getRoles().remove(role);
    }

    /**
     * Helper method to determine if the passed role is present in the roles
     * List.
     */
    public boolean containsRole(Role role) {
        return getRoles() != null && getRoles().contains(role);
    }
    
}