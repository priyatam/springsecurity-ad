package github.priyatam.springsecurity.domain;

import javax.persistence.*;
import java.io.Serializable;

@Entity
public class Role implements Serializable {
    static final private long serialVersionUID = 1L;

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(updatable = false, nullable = false)
    private Long id;

    private String roleName;

    public Role(String roleName) {
        super();
        this.roleName = roleName;
    }

    public String getRoleName() {
        return roleName;
    }

    public Long getId() {
        return id;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append(getRoleName()).append(",");
        return sb.toString();
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result
                + ((getId() == null) ? 0 : getId().hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        Role other = (Role) obj;
        if (getId() == null) {
            if (other.getId() != null)
                return false;
        } else if (!getId().equals(other.getId())) {
            return false;
        } else if (getId().longValue() != (other.getId().longValue()))
            return false;
        System.err.println("FOUND SAME ROLE: " + obj.toString());
        return true;
    }

}