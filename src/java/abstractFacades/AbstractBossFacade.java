/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package abstractFacades;

import security.Hashing;
import exception.CreateException;
import exception.ReadException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.persistence.EntityManager;
import entity.Boss;
import exception.EmailExistException;
import exception.LoginExistException;

/**
 * Restful service for {@link Boss}. Inherits from AbstractFacade. Contains createNamedQuerys from entity 
 * <code>Boss</code> in Area51 application.
 * @author Xabier Carnero, Endika Ubierna, Markel Lopez de Uralde.
 */
public abstract class AbstractBossFacade extends AbstractFacade<Boss> {
    /**
     * Logger for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(AbstractBossFacade.class.getName());  
    /**
     * Class constructor. Call to the super class {@link AbstractFacade}.
     * @param entityClass <code>Boss</code>.
     */  
    public AbstractBossFacade(Class<Boss> entityClass) {
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
     * This method finds all Area51 <code>Boss</code>.
     * @return A list containing <code>Boss</code>.
     * @throws ReadException Thrown when any error produced during the read operation.
     */ 
    public List<Boss> getAllBosses() throws ReadException {
        LOGGER.log(Level.INFO, "Metodo getAllBosses de la clase AbstractBossFacade");
        try {
            return getEntityManager().createNamedQuery("findAllBosses").getResultList();
        } catch (Exception e) {
            throw new ReadException("Error when trying to get all Bosses");
        }
    }
    /**
     * This method finds <code>Boss</code> by the class attribute name.
     * @param name The class attribure name.
     * @return A list of <code>Boss</code>.
     * @throws ReadException Thrown when any error produced during the read operation.
     */
    public List<Boss> getBossesByName(String name) throws ReadException {
        LOGGER.log(Level.INFO, "Metodo getBossesByName de la clase AbstractBossFacade");
        try {
            return getEntityManager().createNamedQuery("findBossesByName")
                    .setParameter("name", name)
                    .getResultList();
        } catch (Exception e) {
            throw new ReadException("Error when trying to get Bosses by name");
        }
    }
    /**
     * Create method. Creates a new <code>Boss</code> instance and stores it in the database. 
     * @param boss An instance of {@link Boss} entity class.
     */
    public void createBoss(Boss boss) throws CreateException, LoginExistException, EmailExistException {
        LOGGER.log(Level.INFO, "Metodo createBoss de la clase AbstractBossFacade");
        try {
            boss.setPassword(Hashing.cifrarTexto(boss.getPassword()));
            super.checkLoginAndEmailNotExist(boss.getLogin(), boss.getEmail());
            super.create(boss);
        } catch (ReadException e) {
            throw new CreateException("Error when trying to create " + boss.toString());
        }
    }
}