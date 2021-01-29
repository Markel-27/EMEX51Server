/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package abstractFacades;

import security.Hashing;
import entity.User;
import entity.Visitor;
import exception.CreateException;
import exception.EmailExistException;
import exception.IncorrectPasswordException;
import exception.LoginExistException;
import exception.LoginNotExistException;
import exception.ReadException;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.persistence.EntityManager;
import security.PrivateKeyServer;
import service.BossFacadeREST;

/**
 * Restful service for <code>Visitor</code>. Inherits from AbstractFacade.
 * Contains createNamadQuerys from entity Visitor in Area51 application.
 * @author Markel Lopez de Uralde, Endika Ubierna, Xabier Carnero.
 */
public abstract class AbstractVisitorFacade extends AbstractFacade<Visitor> {

    /**
     * Logger for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(AbstractVisitorFacade.class.getName());

    /**
     * Class constructor. Call to the super class {@link AbstractFacade}.
     *
     * @param entityClass <code>Visitor</code>.
     */
    public AbstractVisitorFacade(Class<Visitor> entityClass) {
        super(entityClass);
    }

    /**
     * Gets an {@link EntityManager} instance from one restful service from the
     * entities of the Area 51 project.
     *
     * @return An {@link EntityManager} instance.
     */
    @Override
    protected abstract EntityManager getEntityManager();

    /**
     * This method finds all Area51 visitors.
     *
     * @return A list containing visitors.
     * @throws ReadException Thrown when any error produced during the read
     * operation.
     */
    public List<Visitor> getAllVisitors() throws ReadException {
        LOGGER.log(Level.INFO, "Metodo getAllVisitors de la clase AbstractVisitorFacade");
        try {
            return getEntityManager().createNamedQuery("findAllVisitors").getResultList();
        } catch (Exception e) {
            throw new ReadException("Error when trying to get all visitors");
        }
    }

    /**
     * Create method. Creates a new {@link Employee} instance using Hibernate.
     * The latter executes an insert operation against a MySQL database.
     *
     * @param visitor An instance of {@link Visitor} entity class.
     * @throws exception.CreateException
     * @throws exception.LoginExistException
     * @throws exception.EmailExistException
     */
    public void createVisitor(Visitor visitor) throws CreateException, LoginExistException, EmailExistException {
        LOGGER.log(Level.INFO, "Metodo create de la clase AbstractBossFacade");
        try {
            visitor.setPassword(new String(PrivateKeyServer.descifrarTexto(visitor.getPassword())));
            visitor.setPassword(Hashing.cifrarTexto(visitor.getPassword()));
            super.checkLoginAndEmailNotExist(visitor.getLogin(), visitor.getEmail());
            visitor.setVisitado(false);
            visitor.setVisitaRespuesta(false);
            Date date = Date.from(LocalDate.now().atStartOfDay().toInstant(ZoneOffset.UTC));
            visitor.setLastAccess(date);
            visitor.setLastPasswordChange(date);
            super.create(visitor);
        } catch (ReadException e) {
            throw new CreateException("Error when trying to create " + visitor.toString());
        }
    }

    /**
     * This method finds a <code>Visitor</code> by the class attribute name.
     *
     * @param name The class attribure name.
     * @return A list of <code>Visitor</code>.
     * @throws ReadException Thrown when any error produced during the read
     * operation.
     */
    public List<Visitor> getVisitorsByName(String name) throws ReadException {
        LOGGER.log(Level.INFO, "Metodo getVisitorsByName de la clase AbstractVisitorFacade");
        try {
            return getEntityManager().createNamedQuery("findVisitorsByName")
                    .setParameter("name", name)
                    .getResultList();
        } catch (Exception e) {
            throw new ReadException("Error when trying to get visitors by name");
        }
    }

    /**
     * This method finds a Visitor by <code>Login</code> and the compares his
     * <code>Password</code>
     *
     * @param login the param login
     * @param password the param password
     * @return the visitor found
     * @throws ReadException
     * @throws LoginNotExistException
     * @throws IncorrectPasswordException
     */
    public Visitor makeVisitorLogin(String login, String password) throws ReadException, LoginNotExistException, IncorrectPasswordException {
        LOGGER.log(Level.INFO, "Metodo getVisitorsByName de la clase AbstractVisitorFacade");
        List<Visitor> visitors = getAllVisitors();
        for (Visitor v : visitors) {
            if (v.getLogin().equals(login)) {
                password = new String(PrivateKeyServer.descifrarTexto(password));
                password = Hashing.cifrarTexto(password);
                if (v.getPassword().equals(password)) {
                    return v;
                } else {
                    throw new IncorrectPasswordException();
                }
            }
        }
        throw new LoginNotExistException();
    }
}
