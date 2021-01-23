/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package abstractFacades;

import entity.Army;
import entity.Sector;
import exception.ReadException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.persistence.EntityManager;

/**
 * Restful service for {@link Army}. Inherits from AbstractFacade. Contains createNamedQuerys from entity 
 * <code>Army</code> in Area51 application.
 * @author Xabier Carnero.
 */
public abstract class AbstractArmyFacade extends AbstractFacade<Army> {
    /**
     * Logger for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(AbstractArmyFacade.class.getName());
    /**
     * Class constructor. Call to the super class {@link AbstractFacade}.
     * @param entityClass <code>Army</code>.
     */ 
    public AbstractArmyFacade(Class<Army> entityClass) {
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
     * This method finds all Area51 <code>Army</code>.
     * @return A list containing <code>Army</code>.
     * @throws ReadException Thrown when any error produced during the read operation.
     */
    public List<Army> getAllArmys() throws ReadException {
        LOGGER.log(Level.INFO, "Metodo getAllArmys de la clase AbstractArmyFacade");
        try {
            return getEntityManager().createNamedQuery("findAllArmys").getResultList();
        } catch (Exception e) {
            throw new ReadException("Error when trying to get all armys");
        }
    }
    /**
     * This method finds <code>Army</code> by the class attribute name.
     * @param name The class attribure name.
     * @return A list of <code>Army</code>.
     * @throws ReadException Thrown when any error produced during the read operation.
     */
    public List<Army> getArmyByName(String name) throws ReadException {
        LOGGER.log(Level.INFO, "Metodo getArmyByName de la clase AbstractArmyFacade");
        try {
            return getEntityManager().createNamedQuery("findArmyByName")
                    .setParameter("name", name)
                    .getResultList();
        } catch (Exception e) {
            throw new ReadException("Error when trying to get armys by name");
        }
    } 
    /**
     * This method finds <code>Army</code> by the {@link Sector} where are storaged.
     * @param sectorId The <code>Sector</code> id. It's the PK of the entity.
     * @return A list of <code>Army</code>.
     * @throws ReadException Thrown when any error produced during the read operation.
     */
    public List<Army> getArmyBySector(Integer sectorId) throws ReadException{
        LOGGER.log(Level.INFO, "Metodo getArmyBySector de la clase AbstractArmyFacade");
        try {
            return getEntityManager().createNamedQuery("findArmysBySector")
                    .setParameter("sector", getEntityManager().find(Sector.class, sectorId))
                    .getResultList();
        } catch (Exception e) {
            throw new ReadException("Error when trying to get armys by sector");
        }
    }   
    
    public List<Army> findArmyByMunition(Integer ammunition) throws ReadException{
        List<Army> armys = getAllArmys();
        List<Army> armyReturn = new ArrayList();
        for(Army a: armys)
            if(a.getAmmunition()<ammunition)
                armyReturn.add(a);
        return armyReturn;
    }
}
