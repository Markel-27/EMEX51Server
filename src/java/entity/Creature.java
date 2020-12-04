/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package entity;

import java.io.Serializable;
import java.time.LocalDateTime;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.xml.bind.annotation.XmlRootElement;

/**
 *
 * @author 2dam
 */
@Entity
@Table(name="creature",schema="emex51db")
@XmlRootElement
public class Creature implements Serializable {

    private static final long serialVersionUID = 1L;
    /**
     * Identificativo unico para criatura
     */
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Integer idCriatura;
    /**
     * El nombre de la criatura
     */
    private String nombre;
    /**
     * El sector en el que esta la criatura
     */
    @ManyToOne
    private Sector sector;
    /**
     * Fecha en la que llega la criatura
     */
    private LocalDateTime fechaLlegada;
    /**
     * Constructor vacio
     */
    public Creature() {
    }
    /**
     * Constructor lleno
     * @param idCriatura
     * @param nombre
     * @param sector
     * @param fechaLlegada 
     */
    public Creature(Integer idCriatura, String nombre, Sector sector, LocalDateTime fechaLlegada) {
        this.idCriatura = idCriatura;
        this.nombre = nombre;
        this.sector = sector;
        this.fechaLlegada = fechaLlegada;
    }

    public Integer getIdCriatura() {
        return idCriatura;
    }

    public void setIdCriatura(Integer idCriatura) {
        this.idCriatura = idCriatura;
    }

    public String getNombre() {
        return nombre;
    }

    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    public Sector getSector() {
        return sector;
    }

    public void setSector(Sector sector) {
        this.sector = sector;
    }

    public LocalDateTime getFechaLlegada() {
        return fechaLlegada;
    }

    public void setFechaLlegada(LocalDateTime fechaLlegada) {
        this.fechaLlegada = fechaLlegada;
    }
    /**
     * 
     * @return representación entera para instanciar criatura
     */
    @Override
    public int hashCode() {
        int hash = 0;
        hash += (idCriatura != null ? idCriatura.hashCode() : 0);
        return hash;
    }
    /**
     * Sirve para comparar dos criaturas
     * @param object
     * @return 
     */
    @Override
    public boolean equals(Object object) {
        // TODO: Warning - this method won't work in the case the id fields are not set
        if (!(object instanceof Creature)) {
            return false;
        }
        Creature other = (Creature) object;
        if ((this.idCriatura == null && other.idCriatura != null) || (this.idCriatura != null && !this.idCriatura.equals(other.idCriatura))) {
            return false;
        }
        return true;
    }
    /**
     * obtiene el string de la criatura
     * @return 
     */
    @Override
    public String toString() {
        return "creature.Creature[ idCriatura=" + idCriatura + " ]";
    }
}