/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package service;

import abstractFacades.AbstractFacade;
import abstractFacades.AbstractUserFacade;
import entity.User;
import exception.CreateException;
import exception.DeleteException;
import exception.EmailNotExistException;
import exception.IncorrectPasswordException;
import exception.LoginNotExistException;
import exception.PasswordDontMatchException;
import exception.ReadException;
import exception.UpdateException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.ForbiddenException;
import javax.ws.rs.GET;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

/**
 * RESTful service for User entity. Includes CRUD operations.
 *
 * @author Xabier Carnero, Endika Ubierna, Markel Lopez de Uralde
 * @since 04/12/2020
 * @version 1.0
 */
@Stateless
@Path("user")
public class UserFacadeREST extends AbstractUserFacade {

    /**
     * Logger for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(UserFacadeREST.class.getName());
    /**
     * EntityManager for EMEX51CRUDServerPU persistence unit. Injects an
     * {@link EntityManager} instance.
     */
    @PersistenceContext(unitName = "EMEX51CRUDServerPU")
    private EntityManager em;

    /**
     * Class constructor. Call to the super class {@link AbstractFacade}.
     */
    public UserFacadeREST() {
        super(User.class);
    }

    /**
     * Create (Insert) operation after receiving a Post HTTP order.
     *
     * @param entity The user object in xml format.
     */
    @POST
    @Override
    @Consumes({MediaType.APPLICATION_XML})
    public void create(User entity) {
        LOGGER.log(Level.INFO, "Metodo create de la clase UserFacade");
        try {
            super.create(entity);
        } catch (CreateException ex) {
            Logger.getLogger(ArmyFacadeREST.class.getName()).log(Level.SEVERE, null, ex);
            throw new InternalServerErrorException(ex);
        }
    }

    /**
     * Edit (Update) operation after receiving a Delete HTTP order.
     *
     * @param entity The user object in xml format.
     */
    @PUT
    @Consumes({MediaType.APPLICATION_XML})
    @Override
    public void edit(User entity) {
        LOGGER.log(Level.INFO, "Metodo edit de la clase UserFacade");
        try {
            super.edit(entity);
        } catch (UpdateException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }

    /**
     * Remove (Delete) operation after receiving a Delete HTTP order.
     *
     * @param id An id value of an User.
     */
    @DELETE
    @Path("{id}")
    public void remove(@PathParam("id") Integer id) {
        LOGGER.log(Level.INFO, "Metodo remove de la clase UserFacade");
        try {
            super.remove(super.find(id));
        } catch (ReadException | DeleteException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }

    /**
     * Find (Select) operation after receiving a Get HTTP order.
     *
     * @param id An id value of an User.
     * @return A User object in xml format.
     */
    @GET
    @Path("{id}")
    @Produces({MediaType.APPLICATION_XML})
    public User find(@PathParam("id") Integer id) {
        LOGGER.log(Level.INFO, "Metodo find de la clase UserFacade");
        try {
            return super.find(id);
        } catch (ReadException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }

    /**
     * Find (Select) operation after receiving a Get HTTP order.
     *
     * @param login
     * @param password
     * @return A User object in xml format.
     */
    @GET
    @Path("makeLogin/{login}/{password}")
    @Produces({MediaType.APPLICATION_XML})
    public User comprobateLogin(@PathParam("login") String login, @PathParam("password") String password) {
        LOGGER.log(Level.INFO, "Metodo find de la clase UserFacade");
        try {
            return super.login(login, password);
        } catch (IncorrectPasswordException | LoginNotExistException ex) {
            throw new InternalServerErrorException(ex);
        }
    }

    /**
     * This method finds all Area51 <code>User</code>.
     *
     * @return A list of {@link User}.
     */
    @GET
    @Path("all")
    @Produces({MediaType.APPLICATION_XML})
    public List<User> findAllUsers() {
        LOGGER.log(Level.INFO, "Metodo findAllUsers de la clase UsersFacade");
        try {
            return super.getAllUsers();
        } catch (ReadException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }

    /**
     * This method finds an Area51 <code>User</code> whose login attibute is the
     * same as the String parameter.
     *
     * @param login A String. Represents the login attibute of an Area51 user.
     * @return An user.
     */
    @GET
    @Path("login/{login}")
    @Produces({MediaType.APPLICATION_XML})
    public User findUsersByLogin(@PathParam("login") String login) {
        LOGGER.log(Level.INFO, "Metodo find by login de la clase UserFacade");
        try {
            return super.getUserByLogin(login);
        } catch (ReadException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        } catch (LoginNotExistException ex) {
            Logger.getLogger(UserFacadeREST.class.getName()).log(Level.SEVERE, null, ex);
            //Mensaje de vuelta
        }
        return null;
    }

    /**
     * This method sends a mail to recover the password of the User.
     *
     * @param email
     * @return An user.
     */
    @GET
    @Path("sendMail/{email}")
    @Produces({MediaType.APPLICATION_XML})
    public User sendMail(@PathParam("email") String email) throws ForbiddenException, InternalServerErrorException {
        LOGGER.log(Level.INFO, "Metodo send mail de la clase UserFacade");
        try {
            super.sendEmail(email);
        } catch (ReadException | UpdateException ex) {
            Logger.getLogger(UserFacadeREST.class.getName()).log(Level.SEVERE, null, ex);
            throw new InternalServerErrorException(ex);
        } catch (EmailNotExistException ex) {
            Logger.getLogger(UserFacadeREST.class.getName()).log(Level.SEVERE, null, ex);
            //Cambiar por unautorized
            throw new ForbiddenException(ex);
        }
        return null;
    }

    /**
     * This method changes the password of the User.
     *
     * @param email
     * @param tempPass
     * @param newPass
     * @return An user.
     * @throws exception.ReadException
     * @throws exception.UpdateException
     * @throws exception.PasswordDontMatchException
     */
    @GET
    @Path("newPassword/{email}/{tempPass}/{newPass}")
    @Produces({MediaType.APPLICATION_XML})
    public User changePassword(@PathParam("email") String email, @PathParam("tempPass") String tempPass, @PathParam("newPass") String newPass)
            throws ForbiddenException, InternalServerErrorException, ReadException, UpdateException, PasswordDontMatchException {
        LOGGER.log(Level.INFO, "Metodo change password de la clase UserFacade");
        super.newPassword(email, tempPass, newPass);
        return null;
    }

    /**
     * Gets an {@link EntityManager} instance.
     *
     * @return An {@link EntityManager} instance.
     */
    @Override
    protected EntityManager getEntityManager() {
        LOGGER.log(Level.INFO, "Metodo getEntityManager de la clase UserFacade");
        return em;
    }
}
