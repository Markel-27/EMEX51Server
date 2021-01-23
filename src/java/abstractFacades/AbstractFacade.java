/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package abstractFacades;

import entity.Sector;
import entity.SectorType;
import entity.User;
import exception.CreateException;
import exception.DeleteException;
import exception.EmailExistException;
import exception.LoginExistException;
import exception.ReadException;
import exception.UpdateException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.persistence.EntityManager;

/**
 * RESTful service for all the EMEX51 project entities.
 * @author Xabier Carnero, Endika Ubierna, Markel Lopez de Uralde.
 * @since 04/12/2020
 * @version 1.0
 */
public abstract class AbstractFacade<T> {
    /**
     * Logger for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(AbstractFacade.class.getName());
    /**
     * Attribute for this class. Able to handle every type of class.
     */
    private Class<T> entityClass;
    /**
     * Class constructor. Receives en entity class which willtake the place of
     * the generic java type <T>
     * @param entityClass An entity class.
     */
    public AbstractFacade(Class<T> entityClass) {
        this.entityClass = entityClass;
    }
    /**
     * Gets an {@link EntityManager} instance from one restful service from the
     * entities of the Area 51 project.
     * @return An {@link EntityManager} instance.
     */
    protected abstract EntityManager getEntityManager();
    /**
     * Create method. Sends a create order to Hibernate. The latter executes an
     * insert operation against a MySQL database.
     * @param entity An entity class. This Entity replaces the generic Java type
     * <T>.
     * @throws exception.CreateException
     */
    public void create(T entity) throws CreateException {
        LOGGER.log(Level.INFO, "Metodo create de la clase AbstractFacade");
        try {
            getEntityManager().persist(entity);
        } catch (Exception e) {
            throw new CreateException("Error when trying to create " + entity.toString());
        }
    }
    /**
     * Edit method. Sends a edit order to Hibernate. The latter executes an
     * update operation against a MySQL database.
     * @param entity An entity class. This Entity replaces the generic Java type
     * <T>.
     */
    public void edit(T entity) throws UpdateException {
        LOGGER.log(Level.INFO, "Metodo edit de la clase AbstractFacade");
        try {
            getEntityManager().merge(entity);
        } catch (Exception e) {
            throw new UpdateException("Error when trying to update " + entity.toString());
        }
    }
    /**
     * Remove method. Sends a remove order to Hibernate. The latter executes a
     * delete operation against a MySQL database.
     * @param entity An entity class. This Entity replaces the generic Java type
     * <T>.
     */
    public void remove(T entity) throws DeleteException {
        LOGGER.log(Level.INFO, "Metodo remove de la clase AbstractFacade");
        try {
            getEntityManager().remove(getEntityManager().merge(entity));
        } catch (Exception e) {
            throw new DeleteException("Error when trying to delete " + entity.toString());
        }
    }
    /**
     * Find method. Sends a find order to Hibernate. The latter executes a
     * Select operation against a MySQL database Get HTTP petition.
     * @param id The id value.
     * @return An object.
     */
    public T find(Object id) throws ReadException {
        LOGGER.log(Level.INFO, "Metodo find de la clase AbstractFacade");
        try {
            return getEntityManager().find(entityClass, id);
        } catch (Exception e) {
            throw new ReadException("Error when trying to read " + id.toString());
        }
    }
    /**
     * Find operation. Gets an user with the same login or email attribute.
     * @param login The attribute login of an {@link User}.
     * @param email The attribute email of an {@link User}.
     * @throws ReadException Thrown when any error produced during the read operation.
     * @throws LoginExistException Thrown when there is already an existing <code>User</code> with the same login value as the parameter login.
     * @throws EmailExistException Thrown when there is already an existing <code>User</code> with the same email value as the parameter email.
     */
    public void checkLoginAndEmailNotExist(String login, String email) throws ReadException, LoginExistException, EmailExistException {
        LOGGER.log(Level.INFO, "Find user by login method from AbstractFacade");
        List<User> users = getEntityManager().createNamedQuery("findAllUsers").getResultList();
        for (int i = 0; i < users.size(); i++) {
            if (users.get(i).getLogin().compareToIgnoreCase(login) == 0) {
                throw new LoginExistException();
            }
        }
        for (int i = 0; i < users.size(); i++) {
            if (users.get(i).getEmail().compareToIgnoreCase(email) == 0) {
                throw new EmailExistException();
            }
        }
    }
    
    /**
     * Gets a list of <code>Sector</code> where the type is the same as the one passed by parameter..
     * @param type The type of the <code>Sector</code>.
     * @return A list of <code>Sector</code>.
     */
    public List<Sector> findSectorsByType(SectorType type) {
        LOGGER.log(Level.INFO, "Find By Type method from SectorFacade");
        return getEntityManager().createNamedQuery("findSectorByType").setParameter("type", type).getResultList();
    }
}
