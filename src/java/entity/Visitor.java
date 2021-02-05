/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package entity;

import java.io.Serializable;
import java.util.Date;
import java.util.Set;
import static javax.persistence.CascadeType.MERGE;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import static javax.persistence.FetchType.EAGER;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;
import javax.persistence.ManyToOne;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.xml.bind.annotation.XmlRootElement;

/**
 * Entity JPA class for visitor data. This class inherits of the superclass
 * User. The property of this class is dni,requested visitReply, visited,
 * visitReply date. It also contains relational fields for getting the
 * {@link Employee} and the {@link Sector}.
 * @since 23/11/2020
 * @version 1.0
 * @author Xabier Carnero, Endika Ubierna, Markel Lopez de Uralde.
 */
@Entity
//Vamos a tener un campo en la tabla que nos indica que tipo de usuario es
@DiscriminatorValue(value = "VISITOR")
@NamedQueries({
    @NamedQuery(name = "findAllVisitors",
            query = "SELECT v FROM Visitor v"),
    @NamedQuery(name = "findVisitorsByName",
            query = "SELECT v FROM Visitor v WHERE v.fullName = :name"),
    @NamedQuery(name = "porEmploye",
            query = "SELECT v FROM Visitor v WHERE v.employee.id=:id")
})
@XmlRootElement
public class Visitor extends User implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * The DNI of the visitor.
     */
    private String dni;
    /**
     * The request date of the visitReply.
     */
    @Temporal(TemporalType.TIMESTAMP)
    private Date requestedVisitDate;
    /**
     * The response. True or false.
     */
    private Boolean visitReply;
    /**
     * Visited value. True or false.
     */
    private Boolean visited;
    /**
     * The date of the visitors visitReply.
     */
    @Temporal(TemporalType.TIMESTAMP)
    private Date visitDate;
    /**
     * The {@link Employee} who manage the visitors visitReply.
     */
    @ManyToOne
    private Employee employee;
    /**
     * The Set of {@link Sector} visited by the visitor.
     */
    @ManyToMany(fetch = EAGER, cascade = MERGE)
    @JoinTable(schema = "emex51db", name = "visited_sector")
    private Set<Sector> visitedSectors;

    /**
     * Class constructor.
     */
    public Visitor() {
    }

    /**
     * Gets the dni of the visitor.
     * @return The dni value.
     */
    public String getDni() {
        return dni;
    }

    /**
     * Sets the dni of the visitor.
     * @param dni The dni value.
     */
    public void setDni(String dni) {
        this.dni = dni;
    }

    /**
     * Gets the date of the requested visitReply.
     * @return The date of the requested visitReply value.
     */
    public Date getRequestedVisitDate() {
        return requestedVisitDate;
    }

    /**
     * Sets the date of the requested visitReply.
     * @param requestedVisit The date of the requested visitReply value.
     */
    public void setVisitaSolicitada(Date requestedVisit) {
        this.requestedVisitDate = requestedVisit;
    }

    /**
     * Gets the boolean value of the response to the visitReply date request.
     * @return The visitReply response value. True or false.
     */
    public boolean isVisitaRespuesta() {
        return visitReply;
    }

    /**
     * Sets the boolean value of the response to the visitReply date request.
     * @param visitaRespuesta The visitReply response value. True or false.
     */
    public void setVisitaRespuesta(boolean visitaRespuesta) {
        this.visitReply = visitaRespuesta;
    }

    /**
     * Gets the visited value
     * @return The visited value. True or false.
     */
    public boolean isVisitado() {
        return visited;
    }

    /**
     * Sets the visited value.
     * @param visitado The visited value.
     */
    public void setVisitado(boolean visitado) {
        this.visited = visitado;
    }

    /**
     * Gets the date of the visitReply.
     * @return The date of the visitReply value.
     */
    public Date getFechaVisita() {
        return visitDate;
    }

    /**
     * Sets the date of the visitReply.
     * @param fechaVisita The date of the visitReply value.
     */
    public void setFechaVisita(Date fechaVisita) {
        this.visitDate = fechaVisita;
    }

    /**
     * Gets the {@link Employee} who manage the visitReply.
     * @return The {@link Employee} who manage the visitReply value.
     */
    public Employee getEmpleado() {
        return employee;
    }

    /**
     * Sets the {@link Employee} who manage the visitReply.
     * @param empleado The {@link Employee} who manage the visitReply value.
     */
    public void setEmpleado(Employee empleado) {
        this.employee = empleado;
    }

    /**
     * Gets the {@link Sector} visited by the visitor.
     * @return The {@link Sector} value.
     */
    public Set<Sector> getSectores() {
        return visitedSectors;
    }

    /**
     * Sets the {@link Sector} visited by the visitor.
     * @param sectores The {@link Sector} value.
     */
    public void setSectores(Set<Sector> sectores) {
        this.visitedSectors = sectores;
    }
}
