/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package abstractFacades;

import entity.Creature;
import entity.Sector;
import exception.ReadException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.persistence.EntityManager;

/**
 * Restful service for {@link Creature}. Inherits from AbstractFacade. Contains createNamedQuerys from entity 
 * <code>Creature</code> in Area51 application.
 * @author Markel Lopez de Uralde, Endika Ubierna, Xabier Carnero.
 */
public abstract class AbstractCreatureFacade extends AbstractFacade<Creature> {
    /**
     * Logger for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(AbstractCreatureFacade.class.getName()); 
    /**
     * Class constructor. Call to the super class {@link AbstractFacade}.
     * @param entityClass <code>Creature</code>.
     */        
    public AbstractCreatureFacade(Class<Creature> entityClass) {
        super(entityClass);
    }
    /**
     * Gets an {@link EntityManager} instance from one restful service from the
     * entities of the Area 51 project.
     * @return An {@link EntityManager} instance.
     */
    @Override
    protected abstract EntityManager getEntityManager();
    /**
     * This method finds all Area51 <code>Creature</code>.
     * @return A list containing <code>Creature</code>.
     * @throws ReadException Thrown when any error produced during the read operation.
     */   
    public List<Creature> getAllCreatures() throws ReadException {
        LOGGER.log(Level.INFO, "Metodo getAllCreatures de la clase AbstractCreatureFacade");
        try {
            return getEntityManager().createNamedQuery("findAllCreatures").getResultList();
        } catch (Exception e) {
            throw new ReadException("Error when trying to get all creatures");
        }
    }
    /**
     * This method finds <code>Creature</code> by the class attribute name.
     * @param name The class attribure name.
     * @return A list of <code>Creature</code>.
     * @throws ReadException Thrown when any error produced during the read operation.
     */  
    public List<Creature> getCreaturesByName(String name) throws ReadException {
        LOGGER.log(Level.INFO, "Metodo getCreaturesByName de la clase AbstractCreatureFacade");
        try {
            return getEntityManager().createNamedQuery("findCreatureByName")
                    .setParameter("name", name)
                    .getResultList();
        } catch (Exception e) {
            throw new ReadException("Error when trying to get creatures by name");
        }
    }
    /**
     * This method finds <code>Creature</code> by the class attribute especie.
     * @param especie The class attribure especie.
     * @return A list of <code>Creature</code>.
     * @throws ReadException Thrown when any error produced during the read operation.
     */  
    public List<Creature> getCreaturesByEspecie(String species) throws ReadException{
        LOGGER.log(Level.INFO, "Metodo getCreaturesByEspecie de la clase AbstractCreatureFacade");
        try {
            return getEntityManager().createNamedQuery("findCreaturesByEspecie")
                    .setParameter("species", species)
                    .getResultList();
        } catch (Exception e) {
            throw new ReadException("Error when trying to get creatures by especie");
        }
    }
    /**
     * This method finds <code>Creature</code> by the {@link Sector} where are storaged.
     * @param sectorId The <code>Sector</code> id. It's the PK of the entity.
     * @return A list of <code>Creature</code>.
     * @throws ReadException Thrown when any error produced during the read operation.
     */
    public List<Creature> getCreatureBySector(Integer sectorId) throws ReadException{
        LOGGER.log(Level.INFO, "Metodo getCreatureBySector de la clase AbstractCreatureFacade");
        try {
            return getEntityManager().createNamedQuery("findCreaturesBySector")
                    .setParameter("sector", getEntityManager().find(Sector.class, sectorId))
                    .getResultList();
        } catch (Exception e) {
            throw new ReadException("Error when trying to get creatures by sector");
        }
    }
}