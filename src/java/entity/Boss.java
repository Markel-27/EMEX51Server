/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package entity;

import java.io.Serializable;
import java.util.Set;
import javax.persistence.CascadeType;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import static javax.persistence.FetchType.EAGER;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.OneToMany;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlTransient;

/**
 * Entity JPA class for Boss data. This class inherits from de class User. The
 * property of this class is the wage of the boss.It also contains a relational
 * field, a set of {@link Employee} managed by the Boss.
 * @since 23/11/2020
 * @version 1.0
 * @author Xabier Carnero, Endika Ubierna, Markel Lopez de Uralde.
 */
@Entity
//Vamos a tener un campo en la tabla que nos indica que tipo de usuario es
@DiscriminatorValue(value = "BOSS")
@NamedQueries({
    @NamedQuery(name = "findAllBosses",
            query = "SELECT b FROM Boss b"),
    @NamedQuery(name = "findBossesByName",
            query = "SELECT b FROM Boss b WHERE b.fullName = :name")
})
@XmlRootElement
public class Boss extends User implements Serializable {

    private static final long serialVersionUID = 1L;
    /**
     * The Boss of the boss.
     */
    private float wage;
    /**
     * The list of {@link Employee} of the boss.
     */
    @OneToMany(mappedBy = "boss", fetch = EAGER, cascade = CascadeType.MERGE)
    private Set<Employee> employees;

    /**
     * Class constructor.
     */
    public Boss() {
    }

    /**
     * Gets the wages of the boss.
     * @return The Boss value.
     */
    public float getWage() {
        return wage;
    }

    /**
     * Sets the wages of the boss.
     * @param wage The Boss value.
     */
    public void setWage(float wage) {
        this.wage = wage;
    }

    /**
     * Gets the list of {@link Employee} of the boss.
     * @return The Set of {@link Employee} value.
     */
    @XmlTransient
    public Set<Employee> getEmployees() {
        return employees;
    }

    /**
     * Sets the list of {@link Employee} of the boss.
     * @param employees The Set of {@link Employee} value.
     */
    public void setEmployees(Set<Employee> employees) {
        this.employees = employees;
    }
}
