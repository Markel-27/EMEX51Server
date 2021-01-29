/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package abstractFacades;

import entity.Sector;
import entity.SectorContent;
import exception.CreateException;
import exception.DeleteException;
import exception.ReadException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.persistence.EntityManager;

/**
 * Restful service for {@link Sector}. Inherits from AbstractFacade. Contains createNamedQuerys from entity <code>Sector</code> in 
 * Area51 application.
 * @author Markel Lopez de Uralde, Endika Ubierna, Xabier Carnero.
 */
public abstract class AbstractSectorFacade extends AbstractFacade<Sector> {
    /**
     * Logger for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(AbstractSectorFacade.class.getName());
    /**
     * Class constructor. Call to the super class {@link AbstractFacade}.
     * @param entityClass <code>Sector</code>.
     */
    public AbstractSectorFacade(Class<Sector> entityClass) {
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
     * Create method. Sends a create order to Hibernate. The latter executes an
     * insert operation against a MySQL database.
     * @param sector An instance of {@link Sector} entity class.
     */
    public void createSector(Sector sector) throws CreateException {
        LOGGER.log(Level.INFO, "Metodo create de la clase AbstractBossFacade");
        List <Sector> sectores;
        try {
             sectores = getEntityManager().createNamedQuery("findSectorByName").
                setParameter("name",sector.getName()).getResultList();
            if (!sectores.isEmpty())
                throw new CreateException("Incorrect sector name. "+sector.getName()+" already exists.");
            else
                    getEntityManager().persist(sector);
        }catch (RuntimeException e) {
            throw new CreateException("Error trying to create the sector.");
        }
    }
    /**
     * Delete a sector, before deleting it, remove all the data linked to the sector.
     * @param sector An instance of {@link Sector} entity class.
     */
    public void deleteSector(Sector sector) throws DeleteException{
        LOGGER.log(Level.INFO, "Metodo delete de la clase AbstractSectorFacade");
        try{
            for(SectorContent sc:sector.getSectorContent())
                sector.removeContent(sc);
            super.remove(sector);
        }catch (Exception e) {
            throw new DeleteException("Error when trying to delete " + sector.toString());
        }
    }  
    /**
     * This method finds all Area51 sectors.
     * @return A list containing the sectors.
     * @throws ReadException Thrown when any error produced during the read operation. 
     */
    public List<Sector> getAllSectors() throws ReadException {
        LOGGER.log(Level.INFO, "Metodo getAllSectors de la clase AbstractSectorFacade");
        try {
            return getEntityManager().createNamedQuery("findAllSectors").getResultList();
        } catch (Exception e) {
            throw new ReadException("Error when trying to get all sectors");
        }
    }
    /**
     * This method finds a <code>Sector</code> in the database to check if the name is already recorded in the database.
     * @param name A String.
     * @return A list of <code>Sector</code>.
     * @throws ReadException Thrown when any error produced during the read operation.
     */
    public List <Sector> getSectorsByName(String name) throws ReadException {
        LOGGER.log(Level.INFO, "Metodo getSectorsByName de la clase AbstractSectorFacade");
        try {
            return getEntityManager().createNamedQuery("findSectorByName")
                    .setParameter("name", name)
                    .getResultList();
        } catch (Exception e) {
            throw new ReadException("Error when trying to get sectors by name");
        }
    }
    /**
     * This method finds a <code>Sector</code> in the database to check if the type is already recorded in the database.
     * @param type A String.
     * @return A list of <code>Sector</code>.
     * @throws ReadException Thrown when any error produced during the read operation.
     */
    public List<Sector> getSectorsByType(String type) throws ReadException {
        LOGGER.log(Level.INFO, "Metodo getSectorsByType de la clase AbstractSectorFacade");
        try {
            return getEntityManager().createNamedQuery("findSectorByType")
                    .setParameter("type",type)
                    .getResultList();
        } catch (Exception e) {
            throw new ReadException("Error when trying to get sectors by type");
        }
    }
}