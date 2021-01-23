/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package entity;

import java.io.Serializable;
import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.xml.bind.annotation.XmlRootElement;

/** 
 * Entity JPA class for Creature data. This class inherits from de class
 * SectorContent. The property of this class is species.
 *
 * @author Xabier Carnero, Endika Ubierna, Markel Lopez de Uralde.
 * @version 1.0
 * @since 01/12/2020
 */
@Entity
@DiscriminatorValue(value = "CREATURE")
@NamedQueries({
    @NamedQuery(name = "findAllCreatures",
            query = "SELECT c FROM Creature c"),
    @NamedQuery(name = "findCreatureByName",
            query = "SELECT c FROM Creature c WHERE c.name = :name"),
    @NamedQuery(name = "findCreaturesByEspecie",
            query = "SELECT c FROM Creature c WHERE c.species = :species"),
    @NamedQuery(name = "findCreaturesBySector",
            query = "SELECT c FROM Creature c WHERE c.sector = :sector")
})
@XmlRootElement
public class Creature extends SectorContent implements Serializable {

    private static final long serialVersionUID = 1L;
    /**
     * The species of the creature.
     */
    private String species;

    /**
     * Class constructor.
     */
    public Creature() {
        super();
    }

    /**
     * Gets the species of the creature
     * @return The species value.
     */
    public String getSpecies() {
        return species;
    }

    /**
     * Sets the species of the creature
     * @param species The species value.
     */
    public void setSpecies(String species) {
        this.species = species;
    }
}