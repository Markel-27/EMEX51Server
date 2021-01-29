/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package abstractFacades;

import entity.Army;
import entity.Sector;
import entity.SectorContent;
import exception.ReadException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.persistence.EntityManager;

/**
 * Restful service for {@link SectorContent}. Inherits from AbstractFacade. Contains createNamedQuerys from entity 
 * <code>SectorContent</code> in Area51 application.
 * @author Markel Lopez de Uralde, Endika Ubierna, Xabier Carnero.
 */
public abstract class AbstractSectorContentFacade extends AbstractFacade<SectorContent> {
    /**
     * Logger for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(AbstractSectorContentFacade.class.getName());  
    /**
     * Class constructor. Call to the super class {@link AbstractFacade}.
     * @param entityClass <code>SectorContent</code>.
     */    
    public AbstractSectorContentFacade(Class<SectorContent> entityClass) {
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
     * This method finds all Area51 <code>SectorsContent</code>, containing both {@link Army} and <code>Creature</code>..
     * @return A list containing the <code>SectorsContent</code>.
     * @throws ReadException Thrown when any error produced during the read operation. 
     */   
    public List<SectorContent> getAllSectorContents() throws ReadException {
        LOGGER.log(Level.INFO, "Metodo getAllSectorsContents de la clase AbstractSectorContentFacade");
        try {
            return getEntityManager().createNamedQuery("findAllContents").getResultList();
        } catch (Exception e) {
            throw new ReadException("Error when trying to get all SectorContents");
        }
    }
    /**
     * This method finds a <code>SectorContent</code> by the class attribute name.
     * @param name The class attribure name.
     * @return A list of content.
     * @throws ReadException Thrown when any error produced during the read operation.
     */
    public List<SectorContent> getSectorContentsByName(String name) throws ReadException {
        LOGGER.log(Level.INFO, "Metodo getSectorsContentByName de la clase AbstractSectorContentFacade"); 
        try {
            return getEntityManager().createNamedQuery("findContentsByName")
                    .setParameter("name", name)
                    .getResultList();
        } catch (Exception e) {
            throw new ReadException("Error when trying to get SectorContents by name");
        }
    }
    /**
     * This method finds <code>SectorContent</code> by the {@link Sector} where are storaged.
     * @param sectorId The <code>Sector</code> id. It's the PK of the entity.
     * @return A list of <code>SectorContent</code>.
     * @throws ReadException Thrown when any error produced during the read operation.
     */
    public List<SectorContent> getContentBySector(Integer sectorId) throws ReadException{
        LOGGER.log(Level.INFO, "Metodo getContentBySector de la clase AbstractSectorContentFacade");
        try {
            return getEntityManager().createNamedQuery("findContentsBySector")
                    .setParameter("sector", getEntityManager().find(Sector.class, sectorId))
                    .getResultList();
        } catch (Exception e) {
            throw new ReadException("Error when trying to get sectorContent by sector");
        }
    }
}
