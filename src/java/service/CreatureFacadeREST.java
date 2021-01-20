/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package service;

import abstractFacades.AbstractCreatureFacade;
import entity.Creature;
import exception.CreateException;
import exception.DeleteException;
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
import javax.ws.rs.GET;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.NotFoundException;
import javax.ws.rs.POST;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

/**
 * RESTful service for Creature entity. Includes CRUD operations.
 * @author Xabier Carnero, Endika Ubierna, Markel Lopez de Uralde.
 * @since 04/12/2020
 * @version 1.0
 */
@Stateless
@Path("creature")
public class CreatureFacadeREST extends AbstractCreatureFacade {
    /**
     * Logger for this class.
     */
    private static final Logger LOGGER = Logger.getLogger(CreatureFacadeREST.class.getName());
    /**
     * EntityManager for EMEX51CRUDServerPU persistence unit. Injects an
     * {@link EntityManager} instance.
     */
    @PersistenceContext(unitName = "EMEX51CRUDServerPU")
    private EntityManager em;
    /**
     * Class constructor. Call to the super class {@link AbstractFacade}.
     */
    public CreatureFacadeREST() {
        super(Creature.class);
    }
    /**
     * Create (Insert) operation after receiving a Post HTTP order.
     * @param entity The creature object in xml format.
     */
    @POST
    @Override
    @Consumes({MediaType.APPLICATION_XML})
    public void create(Creature entity) {
        LOGGER.log(Level.INFO, "Metodo create de la clase CreatureFacade");
        try {
            super.create(entity);
        } catch (CreateException ex) {
            Logger.getLogger(ArmyFacadeREST.class.getName()).log(Level.SEVERE, null, ex);
            throw new InternalServerErrorException(ex);
        }
    }
    /**
     * Edit (Update) operation after receiving a Delete HTTP order.
     * @param entity The creature object in xml format.
     */
    @PUT
    @Consumes({MediaType.APPLICATION_XML})
    @Override
    public void edit(Creature entity) {
        LOGGER.log(Level.INFO, "Metodo edit de la clase CreatureFacade");
        try {
            super.edit(entity);
        } catch (UpdateException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }
    /**
     * Remove (Delete) operation after receiving a Delete HTTP order.
     * @param id An id value.
     */
    @DELETE
    @Path("{id}")
    public void remove(@PathParam("id") Integer id) {
        LOGGER.log(Level.INFO, "Metodo remove de la clase CreatureFacade");
        try {
            super.remove(super.find(id));
        } catch (ReadException | DeleteException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }
    /**
     * Find (Select) operation after receiving a Get HTTP order.
     * @param id An id value.
     * @return A Creature object in xml format.
     */
    @GET
    @Path("{id}")
    @Produces({MediaType.APPLICATION_XML})
    public Creature find(@PathParam("id") Integer id) {
        LOGGER.log(Level.INFO, "Metodo find de la clase CreatureFacade");
        try {
            return super.find(id);
        } catch (ReadException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }
    /**
     * Gets all the {@link Creature} of Area51.
     * @return A list of <code>Creature</code>
     */
    @GET
    @Path("all")
    @Produces({MediaType.APPLICATION_XML})
    public List<Creature> findAllCreatures() {
        LOGGER.log(Level.INFO, "Metodo findAllCreatures de la clase CreatureFacade");
        try {
            return super.getAllCreatures();
        } catch (ReadException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }
    /**
     * Gets a <code>List</code> of {@link Creature} of Area51 with the same name as the one passed by the parameter.
     * @param name A String with the name of a <code>Creature</code>.
     * @return A list of <code>Creature</code>.
     */
    @GET
    @Path("name/{name}")
    @Produces({MediaType.APPLICATION_XML})
    public List<Creature> findCreatureByName(@PathParam("name") String name) {
        LOGGER.log(Level.INFO, "Metodo find por nombre de la clase CreatureFacade");
        try {
            return super.getCreaturesByName(name);
        } catch (ReadException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }
    /**
     * Gets a List {@link Creature} of Area51 with the same name as the one passed by the parameter.
     * @param sectorId A String with the id of a <code>Sector</code>.
     * @return A list of <code>Creature</code>.
     */
    //Pendientes de hacer
    @GET
    @Path("sector/{sectorId}")
    @Produces({MediaType.APPLICATION_XML})
    public List<Creature> findCreatureBySector(@PathParam("sectorId") Integer sectorId) {
        LOGGER.log(Level.INFO, "Metodo find por sector de la clase CreatureFacade");
        try {
            return super.getCreatureBySector(sectorId);
        } catch (ReadException ex) {
            LOGGER.severe(ex.getMessage());
            throw new InternalServerErrorException(ex.getMessage());
        }
    }
    /**
     * Gets a <code>List</code> of {@link Creature} of Area51 with the same specie as the one passed by the parameter.
     * @param name A String with the specie of a <code>Creature</code>.
     * @return A list of <code>Creature</code>.
     */
    @GET
    @Path("especie/{especie}")
    @Produces({MediaType.APPLICATION_XML})
    public List<Creature> findCreatureByEspecie(@PathParam("especie") String especie) {
        LOGGER.log(Level.INFO, "Metodo find por especie de la clase CreatureFacade");
        try {
            return super.getCreaturesByEspecie(especie);
        } catch (ReadException ex) {
            LOGGER.severe(ex.getMessage());
            throw new NotFoundException(ex);
        }
    }
    /**
     * Gets an {@link EntityManager} instance.
     *
     * @return An {@link EntityManager} instance.
     */
    @Override
    protected EntityManager getEntityManager() {
        LOGGER.log(Level.INFO, "Metodo getEntityManager de la clase CreatureFacade");
        return em;
    }

}