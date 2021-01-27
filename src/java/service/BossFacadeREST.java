/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package service;

import abstractFacades.AbstractBossFacade;
import abstractFacades.AbstractFacade;
import entity.Boss;
import exception.CreateException;
import exception.DeleteException;
import exception.EmailExistException;
import exception.LoginExistException;
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
 * RESTful service for Boss entity. Includes CRUD operations.
 *
 * @author Xabier Carnero, Endika Ubierna, Markel Lopez de Uralde.
 * @since 04/12/2020
 * @version 1.0
 */
@Stateless
@Path("boss")
public class BossFacadeREST extends AbstractBossFacade {

    /**
     * Logger for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(BossFacadeREST.class.getName());
    /**
     * EntityManager for EMEX51CRUDServerPU persistence unit. Injects an
     * {@link EntityManager} instance.
     */
    @PersistenceContext(unitName = "EMEX51CRUDServerPU")
    private EntityManager em;

    /**
     * Class constructor. Call to the super class {@link AbstractFacade}.
     */
    public BossFacadeREST() {
        super(Boss.class);
    }

    /**
     * Create (Insert) operation after receiving a Post HTTP order.
     *
     * @param boss
     */
    @POST
    @Override
    @Consumes({MediaType.APPLICATION_XML})
    public void create(Boss boss) {
        LOGGER.log(Level.INFO, "Metodo create Boss de la clase BossFacade");
        try {
            super.createBoss(boss);
        } catch (CreateException ex) {
            Logger.getLogger(ArmyFacadeREST.class.getName()).log(Level.SEVERE, null, ex);
            throw new InternalServerErrorException(ex);
        } catch (EmailExistException | LoginExistException ex) {
            Logger.getLogger(AbstractBossFacade.class.getName()).log(Level.SEVERE, null, ex);
            throw new ForbiddenException(ex);
        }
    }

    /**
     * Edit (Update) operation after receiving a Delete HTTP order.
     *
     * @param entity The boss object in xml format.
     */
    @PUT
    @Consumes({MediaType.APPLICATION_XML})
    @Override
    public void edit(Boss entity) {
        LOGGER.log(Level.INFO, "Metodo edit de la class BossFacade");
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
     * @param id An id value.
     */
    @DELETE
    @Path("{id}")
    public void remove(@PathParam("id") Integer id) {
        LOGGER.log(Level.INFO, "Metodo remove de la clase BossFacade");
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
     * @param id An id value.
     * @return A Boss object in xml format.
     */
    @GET
    @Path("{id}")
    @Produces({MediaType.APPLICATION_XML})
    public Boss find(@PathParam("id") Integer id) {
        LOGGER.log(Level.INFO, "Metodo find de la clase BossFacade");
        try {
            Boss boss = super.find(id);
            getEntityManager().detach(boss);
            boss.setPassword("");
            return boss;
        } catch (ReadException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }

    /**
     * Gets all the {@link Boss} of Area51.
     *
     * @return A list of <code>Boss</code>
     */
    @GET
    @Path("all")
    @Produces({MediaType.APPLICATION_XML})
    public List<Boss> findAllBosses() {
        LOGGER.log(Level.INFO, "Metodo findAllBosses de la clase BossFacade");
        try {
            List<Boss> bosses = super.getAllBosses();
            for (Boss b : bosses) {
                getEntityManager().detach(b);
                b.setPassword("");
            }
            return bosses;
        } catch (ReadException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }

    /**
     * Gets a <code>List</code> {@link Boss} of Area51 with the same name as the
     * one passed by the parameter.
     *
     * @param name
     * @return A list of <code>Boss</code>.
     */
    @GET
    @Path("name/{name}")
    @Produces({MediaType.APPLICATION_XML})
    public List<Boss> findBossesByName(@PathParam("name") String name) {
        LOGGER.log(Level.INFO, "Metodo find por nombre de la clase BossFacade");
        try {
            List<Boss> bosses = super.getBossesByName(name);
            for (Boss b : bosses) {
                getEntityManager().detach(b);
                b.setPassword("");
            }
            return bosses;
        } catch (ReadException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }

    /**
     * Gets an {@link EntityManager} instance.
     *
     * @return An {@link EntityManager} instance.
     */
    @Override
    protected EntityManager getEntityManager() {
        LOGGER.log(Level.INFO, "Metodo getManager de la clase BossFacade");
        return em;
    }

}
