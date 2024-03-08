CREATE SCHEMA IF NOT EXISTS soso_schema;
SET SEARCH_PATH = soso_schema;

CREATE OR REPLACE FUNCTION set_default_name()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.name IS NULL THEN
        NEW.name := 'unnamed_' || TG_ARGV[0] || '_' || NEW.id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ================== Schedule table ================
CREATE TABLE IF NOT EXISTS schedule (
    id integer PRIMARY KEY GENERATED BY DEFAULT AS IDENTITY,
    name text UNIQUE NOT NULL,
    group_name text DEFAULT NULL, -- this is the group of schedules that are related to each other. e.g. schedules that all belong to the second generation of a genetic algorithm in a population of schedules
    description text DEFAULT NULL,
    reference_time_offset interval DEFAULT '0 seconds' NOT NULL
);

CREATE OR REPLACE TRIGGER schedule_default_name
BEFORE INSERT ON schedule
FOR EACH ROW
EXECUTE FUNCTION set_default_name('schedule');

INSERT INTO schedule (id, name, group_name) 
VALUES (0, 'Default Schedule', NULL) 
ON CONFLICT (id) -- TODO: handle case where we change the default name to some other name that already exists in the database. not important to handle anytime soon (or maybe even ever in our project tbh), but something to think about
DO UPDATE SET name = EXCLUDED.name, group_name = EXCLUDED.group_name;

-- schedule lock - for future stuff
CREATE EXTENSION IF NOT EXISTS btree_gist; -- required for the EXCLUDE constraint with range types
CREATE TABLE IF NOT EXISTS schedule_lock (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    schedule_id integer REFERENCES schedule (id),
    acquisition_time timestamptz DEFAULT CURRENT_TIMESTAMP,
    last_release_time timestamptz DEFAULT CURRENT_TIMESTAMP,
    time_range tstzrange,
    lock_priority integer DEFAULT 0 NOT NULL CHECK (lock_priority >= 0), -- priority would be based on "how many items do I need to schedule? if I need to schedule `delta` amount more than you, i don't care that you have the lock, I will steal the lock from you (delete conflicting row and insert new lock with higher priority)". maybe also consider the new things you will have to schedule that the previous lock owner was trying to schedule, that fall in teh overlap range
    EXCLUDE USING gist (schedule_id WITH =, time_range WITH &&)
);
-- ================== End of Schedule table ================


-- ================== Asset Tables ==================
CREATE TYPE asset_type AS ENUM ('satellite', 'groundstation');
CREATE TABLE IF NOT EXISTS asset (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    name text UNIQUE NOT NULL,
    asset_type asset_type NOT NULL
);

CREATE TABLE IF NOT EXISTS ground_station (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    name text UNIQUE NOT NULL,
    latitude double precision,
    longitude double precision,
    elevation double precision,
    send_mask double precision,
    receive_mask double precision,
    uplink_rate_mbps double precision,
    downlink_rate_mbps double precision,
    reconfig_duration interval NOT NULL DEFAULT '5 minutes',
    asset_type asset_type DEFAULT 'groundstation'::asset_type NOT NULL CHECK (asset_type = 'groundstation')
) INHERITS (asset);

CREATE OR REPLACE TRIGGER ground_station_default_name
BEFORE INSERT ON ground_station
FOR EACH ROW
EXECUTE FUNCTION set_default_name('ground_station');

CREATE TABLE IF NOT EXISTS satellite (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    name text UNIQUE NOT NULL,
    tle json,
    storage_capacity double precision,
    power_capacity double precision,
    battery_capacity_wh double precision DEFAULT (6/60), -- Battery capacity in unit of Wh (watt-hours). Default 6 minute limit, assuming (as is currently the case) that every event that draws power only draws 1 watt
    fov double precision,
    asset_type asset_type DEFAULT 'satellite'::asset_type NOT NULL CHECK (asset_type = 'satellite')
) INHERITS (asset);

CREATE OR REPLACE TRIGGER satellite_default_name
BEFORE INSERT ON satellite
FOR EACH ROW
EXECUTE FUNCTION set_default_name('satellite');
-- ================== End of Asset Tables ==================

-- ================== Order Tables ==================
CREATE TYPE order_type AS ENUM ('imaging', 'maintenance', 'outage');
-- abstract table. do not define constraints on this (including primary/foreign key constraints), as it won't be inherited by the children
CREATE TABLE IF NOT EXISTS system_order (
	id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
	schedule_id integer NOT NULL DEFAULT 0 REFERENCES schedule (id), -- default schedule has id 0
	asset_id integer DEFAULT NULL, -- optional field. if null, then the order can be fulfilled by any asset
	start_time timestamptz NOT NULL, -- maybe rename to make it clear that it is not the actual start/end time of the event, but the window in which it can be scheduled
	end_time timestamptz NOT NULL,
	duration interval NOT NULL,
	delivery_deadline timestamptz,
	visits_remaining integer NOT NULL DEFAULT 1 CHECK (visits_remaining>=0),
	revisit_frequency interval DEFAULT '0 days', -- if revisit_frequency is 0 days, then it is a one-time order
	revisit_frequency_max interval DEFAULT NULL,
	priority integer DEFAULT 1 NOT NULL CHECK (priority >= 0),
    order_type order_type DEFAULT NULL NOT NULL,
	CONSTRAINT valid_end_time CHECK (end_time >= start_time),
	CONSTRAINT valid_delivery_deadline CHECK (delivery_deadline >= end_time),
	CONSTRAINT valid_visits_remaining CHECK (visits_remaining>=0)
);

CREATE TABLE IF NOT EXISTS transmitted_order (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    uplink_size double precision DEFAULT 0.001 NOT NULL, -- command to transmit to asset is 1KB TODO: replace with actual value in bytes
    downlink_size double precision DEFAULT 0.0 NOT NULL,
    CONSTRAINT valid_uplink_size CHECK (uplink_size >= 0),
    CONSTRAINT valid_downlink_size CHECK (downlink_size >= 0)
) INHERITS (system_order);

CREATE TYPE image_type AS ENUM ('low', 'medium', 'spotlight');
CREATE TABLE IF NOT EXISTS image_order (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    schedule_id integer REFERENCES schedule (id),
    latitude double precision,
    longitude double precision,
    image_type image_type,
    duration interval NOT NULL,
    downlink_size double precision DEFAULT NULL NOT NULL, -- default is NULL so it is populated by the image order BEFPRE INSERT trigger
    power_usage double precision DEFAULT 1.0 NOT NULL,
    order_type order_type DEFAULT 'imaging'::order_type NOT NULL,
    CONSTRAINT valid_order_type CHECK (order_type = 'imaging')
) INHERITS (transmitted_order);

-- TODO: it may be better to do this in the application level, not the database level
CREATE OR REPLACE FUNCTION set_default_imaging_values()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.downlink_size IS NULL THEN
        CASE NEW.image_type 
            WHEN 'low' THEN 
				NEW.downlink_size := 128.0; -- size in MB
            WHEN 'medium' THEN 
                NEW.downlink_size := 256.0; -- size in MB
            WHEN 'spotlight' THEN 
                NEW.downlink_size := 512.0; -- size in MB
        END CASE;
    END IF;
    IF NEW.duration IS NULL THEN
        CASE NEW.image_type 
            WHEN 'low' THEN 
                NEW.duration := '20 seconds'::interval;
            WHEN 'medium' THEN 
                NEW.duration := '45 seconds'::interval;
            WHEN 'spotlight' THEN 
                NEW.duration := '120 seconds'::interval;
        END CASE;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER set_default_imaging_values_trigger
BEFORE INSERT ON image_order
FOR EACH ROW
EXECUTE FUNCTION set_default_imaging_values();

CREATE TABLE IF NOT EXISTS maintenance_order (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    schedule_id integer REFERENCES schedule (id),
    operations_flag boolean,
    description text,
    asset_id integer NOT NULL REFERENCES satellite (id), -- maintenance orders must be performed on a specific asset. TODO: My assumption is that we don't have maintenance orders for groundstations. veryfy with tsa.
    power_usage double precision DEFAULT 0.0 NOT NULL,
    order_type order_type DEFAULT 'maintenance'::order_type NOT NULL,
    CONSTRAINT valid_order_type CHECK (order_type = 'maintenance')
) INHERITS (transmitted_order);

-- abstract table. do not define constraints on this (including primary/foreign key constraints), as it won't be inherited by the children
CREATE TABLE IF NOT EXISTS outage_order (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    asset_id integer NOT NULL,
    asset_type asset_type NOT NULL,
    order_type order_type DEFAULT 'outage'::order_type NOT NULL CHECK (order_type = 'outage')
) INHERITS (system_order);

CREATE TABLE IF NOT EXISTS ground_station_outage_order (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    schedule_id integer REFERENCES schedule (id),
    asset_id integer NOT NULL REFERENCES ground_station (id),
    asset_type asset_type DEFAULT 'groundstation'::asset_type NOT NULL CHECK (asset_type = 'groundstation')
) INHERITS (outage_order);

CREATE INDEX IF NOT EXISTS ground_station_outage_order_start_time_index ON ground_station_outage_order (start_time);
CREATE INDEX IF NOT EXISTS ground_station_outage_order_end_time_index ON ground_station_outage_order (end_time);

CREATE TABLE IF NOT EXISTS satellite_outage_order (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    schedule_id integer REFERENCES schedule (id),
    asset_id integer NOT NULL REFERENCES satellite (id),
    asset_type asset_type DEFAULT 'satellite'::asset_type NOT NULL CHECK (asset_type = 'satellite')
) INHERITS (outage_order);

CREATE INDEX IF NOT EXISTS satellite_outage_order_start_time_index ON satellite_outage_order (start_time);
CREATE INDEX IF NOT EXISTS satellite_outage_order_end_time_index ON satellite_outage_order (end_time);


-- These tables are for tracking what time periods in which we have completely processed the capture or contact opportunities
-- This is necessary as we have the requirement that we should be able to accomodate for changing reference time (which will mean we have to compute past contacts potentially)
-- so tracking this allows us to be able to do that without having to recompute everything from scratch or do redundant work
CREATE TYPE processing_status AS ENUM ('processing', 'processed');
CREATE TABLE IF NOT EXISTS capture_processing_block (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY, -- only here so we will be able to automap the table in sqlalchemy. a key is not really needed.
    satellite_id integer REFERENCES satellite (id) NOT NULL,
    image_type image_type NOT NULL,
    latitude double precision NOT NULL,
    longitude double precision NOT NULL,
    time_range tstzrange NOT NULL,
	status processing_status DEFAULT 'processing'::processing_status NOT NULL,
    CONSTRAINT valid_time_range CHECK (lower(time_range) < upper(time_range)),
    EXCLUDE USING gist (satellite_id WITH =, latitude WITH =, longitude WITH =, time_range WITH &&) -- no overlapping time ranges
);

CREATE TABLE IF NOT EXISTS contact_processing_block (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY, -- only here so we will be able to automap the table in sqlalchemy. a key is not really needed.
    satellite_id integer REFERENCES satellite (id) NOT NULL,
    groundstation_id integer REFERENCES ground_station (id) NOT NULL,
    time_range tstzrange NOT NULL,
	status processing_status DEFAULT 'processing'::processing_status NOT NULL,
    CONSTRAINT valid_time_range CHECK (lower(time_range) < upper(time_range)),
	EXCLUDE USING gist (satellite_id WITH =, groundstation_id WITH =, time_range WITH &&) -- no overlapping time ranges
);

CREATE TABLE IF NOT EXISTS eclipse_processing_block (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY, -- only here so we will be able to automap the table in sqlalchemy. a key is not really needed.
    satellite_id integer REFERENCES satellite (id) NOT NULL,
    time_range tstzrange NOT NULL,
	status processing_status DEFAULT 'processing'::processing_status NOT NULL,
    CONSTRAINT valid_time_range CHECK (lower(time_range) < upper(time_range)),
    EXCLUDE USING gist (satellite_id WITH =, time_range WITH &&) -- no overlapping time ranges
);

CREATE TABLE IF NOT EXISTS ground_station_request (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    schedule_id integer NOT NULL REFERENCES schedule (id),
    station_id integer NOT NULL REFERENCES ground_station (id),
    signal_acquisition_time timestamp with time zone,
    signal_loss_time timestamp with time zone
);

CREATE INDEX IF NOT EXISTS ground_station_request_signal_acquisition_index ON ground_station_request (signal_acquisition_time);
CREATE INDEX IF NOT EXISTS ground_station_request_signal_loss_index ON ground_station_request (signal_loss_time);

CREATE TYPE schedule_request_status AS ENUM ('received', 'processing', 'rejected', 'declined', 'displaced', 'scheduled', 'sent_to_gs');
CREATE TABLE IF NOT EXISTS schedule_request (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    schedule_id integer NOT NULL REFERENCES schedule (id),
    order_id integer NOT NULL,
    order_type order_type, -- needed because order_id is not unique across the different order types
    asset_id integer DEFAULT NULL, -- it is null in the case where we don't care what asset it is performed on
    asset_type asset_type DEFAULT NULL,
    window_start timestamptz,
    window_end timestamptz CHECK (window_end >= window_start),
    utc_window_time_range tsrange GENERATED ALWAYS AS (tsrange(window_start AT TIME ZONE 'UTC', window_end AT TIME ZONE 'UTC')) STORED,
    duration interval NOT NULL,
    delivery_deadline timestamptz CHECK (delivery_deadline >= window_end), -- can be null if there is nothing to be delivered back, e.g. it is null for maintenance requests
    uplink_size double precision NOT NULL DEFAULT 0 CHECK (uplink_size >= 0), -- there are some things we don't uplink/downlink, they will just have the default value of 0 for their uplink/downlink data size
    downlink_size double precision NOT NULL DEFAULT 0 CHECK (downlink_size >= 0),
    power_usage double precision NOT NULL DEFAULT 0.0 CHECK (power_usage >= 0.0),
    priority integer DEFAULT 1 NOT NULL CHECK (priority >= 0),
    -- autogenerated, don't worry about this
    status schedule_request_status DEFAULT 'received'::schedule_request_status NOT NULL,
    status_message text DEFAULT NULL,
    requested_at timestamptz DEFAULT current_timestamp,
    UNIQUE (order_type, order_id, window_start)
);

CREATE TYPE event_type AS ENUM ('imaging', 'maintenance', 'outage', 'contact', 'eclipse', 'capture');

-- ================== Abstract tables for Scheduled Events ==================
-- NOTE: Do not define constraints on these tables (including primary/foreign key constraints), as it won't be inherited by the children
CREATE TABLE IF NOT EXISTS scheduled_event (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    schedule_id integer NOT NULL DEFAULT 0, -- this is the schedule we are in the process of constructing. default schedule has id 0
    asset_id integer NOT NULL, -- this is the resource we are scheduling to.
    request_id integer DEFAULT NULL REFERENCES schedule_request(id),
    start_time timestamptz NOT NULL,
    duration interval NOT NULL,
    utc_time_range tsrange GENERATED ALWAYS AS (tsrange(start_time AT TIME ZONE 'UTC', (start_time  AT TIME ZONE 'UTC') + duration)) STORED,
    window_start timestamptz DEFAULT NULL CHECK (window_start <= start_time), -- this is the start of the buffer zone. it is the earliest time this event can be shifted to
    window_end timestamptz DEFAULT NULL CHECK (window_end >= start_time+duration),
    -- these fields are auto-generated always
    event_type event_type NOT NULL,
    asset_type asset_type NOT NULL
);

CREATE TABLE IF NOT EXISTS windowed_event (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    window_start timestamptz NOT NULL,
    window_end timestamptz NOT NULL
) INHERITS (scheduled_event);

CREATE OR REPLACE FUNCTION set_default_event_window()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.window_start IS NULL THEN
        NEW.window_start := NEW.start_time;
    END IF;
    IF NEW.window_end IS NULL THEN
        NEW.window_end := NEW.start_time + NEW.duration;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER set_default_event_window_trigger
BEFORE INSERT ON windowed_event
FOR EACH ROW
EXECUTE FUNCTION set_default_event_window();

CREATE TABLE IF NOT EXISTS static_events (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    request_id integer DEFAULT NULL CHECK (request_id IS NULL),
	window_start timestamptz DEFAULT NULL CHECK (window_start IS NULL),
	window_end timestamptz DEFAULT NULL CHECK (window_end IS NULL)
) INHERITS (scheduled_event);
-- ================== End of Abstract tables for Scheduled Events ==================

CREATE TABLE IF NOT EXISTS contact_event (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    schedule_id integer NOT NULL REFERENCES schedule (id),
    asset_id integer NOT NULL REFERENCES satellite (id),
    groundstation_id integer NOT NULL REFERENCES ground_station (id),
    uplink_rate_mbps double precision NOT NULL CHECK (uplink_rate_mbps>=0),
    downlink_rate_mbps double precision NOT NULL CHECK (downlink_rate_mbps>=0),
    total_uplink_size double precision DEFAULT 0 NOT NULL CHECK (total_uplink_size>=0), -- accumulated size of all the transmitted_events that are scheduled to be uplinked during this contact
    total_downlink_size double precision DEFAULT 0 NOT NULL CHECK (total_downlink_size>=0),
    total_transmission_time double precision GENERATED ALWAYS AS (
        (CASE WHEN uplink_rate_mbps = 0 THEN 0 ELSE total_uplink_size/uplink_rate_mbps END) + 
        (CASE WHEN downlink_rate_mbps = 0 THEN 0 ELSE total_downlink_size/downlink_rate_mbps END)
    ) STORED,
    -- the fields below are autogenerated by the database. don't worry about them.
    event_type event_type DEFAULT 'contact'::event_type NOT NULL CHECK (event_type = 'contact'),
    asset_type asset_type DEFAULT 'satellite'::asset_type NOT NULL CHECK (asset_type = 'satellite')
) INHERITS (static_events);

CREATE OR REPLACE FUNCTION populate_contact_event_rates()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.uplink_rate_mbps IS NULL THEN
        SELECT uplink_rate_mbps INTO NEW.uplink_rate_mbps
        FROM ground_station
        WHERE id = NEW.groundstation_id;
    END IF;
    
    IF NEW.downlink_rate_mbps IS NULL THEN
        SELECT downlink_rate_mbps INTO NEW.downlink_rate_mbps
        FROM ground_station
        WHERE id = NEW.groundstation_id;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER populate_contact_event_rates_trigger
BEFORE INSERT ON contact_event
FOR EACH ROW
EXECUTE FUNCTION populate_contact_event_rates();

CREATE INDEX IF NOT EXISTS contact_event_start_time_index ON contact_event (start_time);
CREATE INDEX IF NOT EXISTS contact_event_asset_index ON contact_event (asset_id);

-- This table is for tracking the capture opportunities - when a location of interest is in view of a satellite.
-- Useful for finding potential opportunities for imaging
CREATE TABLE IF NOT EXISTS capture_opportunity (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    schedule_id integer REFERENCES schedule (id),
    asset_id integer REFERENCES satellite (id),
    image_type image_type,
    latitude double precision NOT NULL, -- TODO: Use PostGIS to store the coordinates as a point in the future
    longitude double precision NOT NULL,
    -- the fields below are autogenerated by the database. don't worry about them.
    event_type event_type DEFAULT 'capture'::event_type NOT NULL CHECK (event_type = 'capture'),
    asset_type asset_type DEFAULT 'satellite'::asset_type NOT NULL CHECK (asset_type = 'satellite')
) INHERITS (static_events);

CREATE TABLE IF NOT EXISTS scheduled_outage (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
	window_start timestamptz DEFAULT NULL CHECK (window_start IS NULL),
	window_end timestamptz DEFAULT NULL CHECK (window_end IS NULL),
    outage_reason text DEFAULT NULL,
    event_type event_type DEFAULT 'outage'::event_type NOT NULL CHECK (event_type = 'outage')
) INHERITS (scheduled_event);

CREATE TABLE IF NOT EXISTS ground_station_outage (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    schedule_id integer REFERENCES schedule (id),
    asset_id integer REFERENCES ground_station(id),
    request_id integer REFERENCES schedule_request(id),
    -- the fields below are autogenerated by the database. don't worry about them.
    asset_type asset_type DEFAULT 'groundstation'::asset_type NOT NULL CHECK (asset_type = 'groundstation')
) INHERITS (scheduled_outage);

CREATE INDEX IF NOT EXISTS ground_station_outage_start_time_index ON ground_station_outage (start_time);
CREATE INDEX IF NOT EXISTS ground_station_outage_asset_index ON ground_station_outage (asset_id);

CREATE TABLE IF NOT EXISTS satellite_outage (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    schedule_id integer REFERENCES schedule (id),
    asset_id integer REFERENCES satellite (id),
    request_id integer REFERENCES schedule_request (id),
    -- the fields below are autogenerated by the database. don't worry about them.
    asset_type asset_type DEFAULT 'satellite'::asset_type NOT NULL CHECK (asset_type = 'satellite')
) INHERITS (scheduled_outage);

CREATE INDEX IF NOT EXISTS satellite_outage_start_time_index ON satellite_outage (start_time);
CREATE INDEX IF NOT EXISTS satellite_outage_asset_index ON satellite_outage (asset_id);

CREATE TABLE IF NOT EXISTS satellite_eclipse(
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    schedule_id integer REFERENCES schedule (id),
    asset_id integer REFERENCES satellite (id),
    -- the fields below are autogenerated by the database. don't worry about them.
    event_type event_type DEFAULT 'eclipse'::event_type NOT NULL CHECK (event_type = 'eclipse'),
    asset_type asset_type DEFAULT 'satellite'::asset_type NOT NULL CHECK (asset_type = 'satellite')
) INHERITS (static_events);

CREATE INDEX IF NOT EXISTS satellite_eclipse_start_time_index ON satellite_eclipse (start_time);
CREATE INDEX IF NOT EXISTS satellite_eclipse_asset_index ON satellite_eclipse (asset_id);

-- abstract table. do not define constraints on this (including primary/foreign key constraints), as it won't be inherited by the children
CREATE TABLE IF NOT EXISTS transmitted_event (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    schedule_id integer REFERENCES schedule (id),
    asset_id integer REFERENCES satellite (id),
    request_id integer NOT NULL REFERENCES schedule_request(id),
    uplink_contact_id integer NOT NULL REFERENCES contact_event (id),
    downlink_contact_id integer DEFAULT NULL REFERENCES contact_event (id), -- it is nullable because not all events have data they have to transmit back to groundstation
    uplink_size double precision NOT NULL CHECK (uplink_size>=0),
    downlink_size double precision NOT NULL CHECK (downlink_size>=0),
    power_usage double precision NOT NULL DEFAULT 0.0 CHECK (power_usage>=0),
    priority integer NOT NULL CHECK (priority>=0), -- used to calculate throughput
    -- the fields below are autogenerated by the database. don't worry about them.
    asset_type asset_type DEFAULT 'satellite'::asset_type NOT NULL CHECK (asset_type = 'satellite')
) INHERITS (windowed_event);

CREATE INDEX IF NOT EXISTS transmitted_event_start_time_index ON transmitted_event (start_time);
CREATE INDEX IF NOT EXISTS transmitted_event_asset_index ON transmitted_event (asset_id);
CREATE INDEX IF NOT EXISTS transmitted_event_schedule_index ON transmitted_event (schedule_id);
CREATE INDEX IF NOT EXISTS transmitted_event_type_index ON transmitted_event (event_type);

CREATE OR REPLACE FUNCTION increment_contact_transmitted_data_size() RETURNS TRIGGER AS $$
BEGIN
    -- lock contact events for update
    PERFORM * FROM contact_event
    WHERE id=NEW.uplink_contact_id OR id=NEW.downlink_contact_id
    FOR UPDATE;

    -- increment the uplink/downlink sizes of corresponding contact events
    UPDATE contact_event SET total_uplink_size = total_uplink_size + NEW.uplink_size
    WHERE id=NEW.uplink_contact_id;

    UPDATE contact_event SET total_downlink_size = total_downlink_size + NEW.downlink_size
    WHERE id=NEW.downlink_contact_id;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION decrement_contact_transmitted_data_size() RETURNS TRIGGER AS $$
BEGIN
    -- lock contact events for update
    PERFORM * FROM contact_event 
    WHERE id=NEW.uplink_contact_id OR id=NEW.downlink_contact_id
    FOR UPDATE;

    -- increment the uplink/downlink sizes of corresponding contact events
    UPDATE contact_event SET total_uplink_size = total_uplink_size - NEW.uplink_size
    WHERE id=NEW.uplink_contact_id;

    UPDATE contact_event SET total_downlink_size = total_downlink_size - NEW.downlink_size
    WHERE id=NEW.downlink_contact_id;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TABLE IF NOT EXISTS scheduled_imaging (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    schedule_id integer REFERENCES schedule (id),
    asset_id integer REFERENCES satellite (id),
    request_id integer NOT NULL REFERENCES schedule_request(id),
    uplink_contact_id integer NOT NULL REFERENCES contact_event (id),
    downlink_contact_id integer DEFAULT NULL REFERENCES contact_event (id), -- it is nullable because not all events have data they have to transmit back to groundstation
    power_usage double precision DEFAULT 1.0,
    -- the fields below are autogenerated by the database. don't worry about them.
    event_type event_type DEFAULT 'imaging'::event_type NOT NULL CHECK (event_type = 'imaging')
) INHERITS (transmitted_event);

CREATE TRIGGER increment_contact_transmitted_data_size_trigger
AFTER INSERT ON scheduled_imaging
FOR EACH ROW EXECUTE FUNCTION increment_contact_transmitted_data_size();

CREATE TRIGGER decrement_contact_transmitted_data_size_trigger
AFTER DELETE ON scheduled_imaging
FOR EACH ROW EXECUTE FUNCTION decrement_contact_transmitted_data_size();

CREATE TABLE IF NOT EXISTS scheduled_maintenance (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    schedule_id integer REFERENCES schedule (id),
    asset_id integer REFERENCES satellite (id),
    request_id integer NOT NULL REFERENCES schedule_request(id),
    uplink_contact_id integer NOT NULL REFERENCES contact_event (id),
    downlink_contact_id integer DEFAULT NULL REFERENCES contact_event (id), -- it is nullable because not all events have data they have to transmit back to groundstation
    -- the fields below are autogenerated by the database. don't worry about them.
    event_type event_type DEFAULT 'maintenance'::event_type NOT NULL CHECK (event_type = 'maintenance')
) INHERITS (transmitted_event);

CREATE TRIGGER increment_contact_transmitted_data_size_trigger
AFTER INSERT ON scheduled_maintenance
FOR EACH ROW EXECUTE FUNCTION increment_contact_transmitted_data_size();

CREATE TRIGGER decrement_contact_transmitted_data_size_trigger
AFTER DELETE ON scheduled_maintenance
FOR EACH ROW EXECUTE FUNCTION decrement_contact_transmitted_data_size();

CREATE TABLE IF NOT EXISTS outbound_schedule(
	id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
	contact_id integer unique REFERENCES contact_event (id),
	satellite_name text NOT NULL REFERENCES satellite (name),
	activity_window timestamptz[] NOT NULL,
	image_activities json[],
	maintenance_activities json[],
	downlink_activities json,
	schedule_status text DEFAULT NULL --"created" at creation, "updated" when a change is made , "sent_to_gs" when sent to the ground station, "cancelled" when cancelled
);

CREATE TYPE asset_state AS (
    storage double precision,
    storage_util double precision,
    throughput double precision,
    energy_usage double precision,
    power_draw double precision
);

CREATE OR REPLACE FUNCTION default_asset_state()
RETURNS asset_state AS $$
BEGIN
    RETURN (0.0, 0.0, 0.0, 0.0, 0.0)::asset_state;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION add_asset_states(state1 asset_state, state2 asset_state)
RETURNS asset_state AS $$
DECLARE
    result asset_state;
BEGIN
    result := (
        (state1).storage + (state2).storage,
        (state1).storage_util + (state2).storage_util,
        (state1).throughput + (state2).throughput,
        (state1).energy_usage + (state2).energy_usage,
        (state1).power_draw + (state2).power_draw
    );
    RETURN result;
END;
$$ LANGUAGE plpgsql;

CREATE AGGREGATE sum (asset_state)
(
    sfunc = add_asset_states,
    stype = asset_state,
    initcond = '(0.0, 0.0, 0.0, 0.0, 0.0)'
);

CREATE OPERATOR + (
    leftarg = asset_state,
    rightarg = asset_state,
    function = add_asset_states,
    commutator = +
);

-- TODO: This view below can be optimized by turning it into a table, and adding triggers for whenever new relevant events are added, to ensure the data stays consistent. This speeds up the whole scheduling algorithm as the algorithm depends on this table heavily
CREATE VIEW eventwise_asset_state_change AS
    -- Three cases where the satellite's state changes. (calculate your state_delta in it's respective case, and leave it as 0)
    -- CASE 1: when we are uplinking the command (e.g. command to take image is uplinked)
    SELECT transmitted_event.schedule_id,
        transmitted_event.asset_id,
        transmitted_event.asset_type,
        contact.start_time as snapshot_time, -- state changes at point of contact (when uplink actually occurs)
        transmitted_event.uplink_size as storage_delta,
        0.0 as throughput_delta,
        0.0 as energy_usage_under_eclipse_delta,
        0.0 as power_draw_delta
    FROM transmitted_event, contact_event as contact
    WHERE transmitted_event.schedule_id=contact.schedule_id
        AND transmitted_event.asset_id=contact.asset_id
        AND transmitted_event.uplink_contact_id=contact.id
    UNION ALL
    -- CASE 2: when the command starts being executed (e.g. image is taken)
    SELECT transmitted_event.schedule_id,
        transmitted_event.asset_id,
        transmitted_event.asset_type,
        transmitted_event.start_time as snapshot_time, -- state changes at point of execution (when the event is actually scheduled to happen on the satellite)
        transmitted_event.downlink_size - transmitted_event.uplink_size as storage_delta, -- the command data that was uplinked can be deleted now as the command has been executed. The result of the command now takes up space.
        1.0*transmitted_event.priority as throughput_delta,
        0.0 as energy_usage_under_eclipse_delta,
        0.0 as power_draw_delta
    FROM transmitted_event
    WHERE transmitted_event.downlink_contact_id IS NOT NULL
    UNION ALL
    -- CASE 3: when the result of the command is being downlinked (e.g. image is being downlinked)
    SELECT transmitted_event.schedule_id,
        transmitted_event.asset_id,
        transmitted_event.asset_type,
        contact.start_time as snapshot_time, -- state changes at point of contact (when downlink actually occurs. we arbitrarily chose downlink_start_time instead of downlink_end_time. which is better to use is debatable, i can't think of a strong enough reason as to why one way and not the other)
        (-1.0)*transmitted_event.downlink_size as storage_delta,
        0.0 as throughput_delta,
        0.0 as energy_usage_under_eclipse_delta,
        0.0 as power_draw_delta
    FROM transmitted_event, contact_event as contact
    WHERE transmitted_event.schedule_id=contact.schedule_id
        AND transmitted_event.asset_id=contact.asset_id
        AND transmitted_event.downlink_contact_id=contact.id
        -- TODO: union changes corresponding to groundstation eventwise state changes
    UNION ALL
    -- CASE 4: event/eclipse overlap starts (event starts occuring during satellite eclipse period)
    SELECT transmitted_event.schedule_id,
        transmitted_event.asset_id,
        transmitted_event.asset_type,
        GREATEST(transmitted_event.start_time, eclipse.start_time) as snapshot_time,
        0.0 as storage_delta,
        0.0 as throughput_delta,
        (
            transmitted_event.power_usage * -- energy = power*time
            EXTRACT(EPOCH FROM (
                upper(transmitted_event.utc_time_range * eclipse.utc_time_range) - lower(transmitted_event.utc_time_range * eclipse.utc_time_range)
            ))
        ) as energy_usage_under_eclipse_delta,
        transmitted_event.power_usage as power_draw_delta
    FROM transmitted_event, satellite_eclipse as eclipse
    WHERE transmitted_event.schedule_id=eclipse.schedule_id
        AND transmitted_event.asset_type=eclipse.asset_type
        AND transmitted_event.asset_id=eclipse.asset_id
        AND eclipse.utc_time_range && transmitted_event.utc_time_range
    UNION ALL
    -- CASE 5: event/eclipse overlap ends (event ends occuring during satellite eclipse period)
    SELECT transmitted_event.schedule_id,
        transmitted_event.asset_id,
        transmitted_event.asset_type,
        LEAST(
            transmitted_event.start_time+transmitted_event.duration,
            eclipse.start_time+eclipse.duration
        ) as snapshot_time,
        0.0 as storage_delta,
        0.0 as throughput_delta,
        0.0 as energy_usage_under_eclipse_delta,
        -transmitted_event.power_usage as power_draw_delta
    FROM transmitted_event, satellite_eclipse as eclipse
    WHERE transmitted_event.schedule_id=eclipse.schedule_id
        AND transmitted_event.asset_type=eclipse.asset_type
        AND transmitted_event.asset_id=eclipse.asset_id
        AND eclipse.utc_time_range && transmitted_event.utc_time_range
    UNION ALL
    -- CASE 6: eclipse has ended
    SELECT transmitted_event.schedule_id,
        transmitted_event.asset_id,
        transmitted_event.asset_type,
        (eclipse.start_time+eclipse.duration) as snapshot_time,
        0.0 as storage_delta,
        0.0 as throughput_delta,
        -SUM(
            transmitted_event.power_usage * -- energy = power*time
            EXTRACT(EPOCH FROM (
                upper(transmitted_event.utc_time_range * eclipse.utc_time_range) - lower(transmitted_event.utc_time_range * eclipse.utc_time_range)
            ))
        ) as energy_usage_under_eclipse_delta,
        0.0 as power_draw_delta
    FROM transmitted_event, satellite_eclipse as eclipse
    WHERE transmitted_event.schedule_id=eclipse.schedule_id
        AND transmitted_event.asset_type=eclipse.asset_type
        AND transmitted_event.asset_id=eclipse.asset_id
        AND eclipse.utc_time_range && transmitted_event.utc_time_range
    GROUP BY transmitted_event.schedule_id,
        transmitted_event.asset_id,
        transmitted_event.asset_type,
        eclipse.start_time,
        eclipse.duration;

CREATE VIEW satellite_state_change AS
SELECT event_change.schedule_id, 
    event_change.asset_id, 
    event_change.asset_type,
    snapshot_time, 
    (
        sum(storage_delta),
        sum(storage_delta) / storage_capacity,
        sum(throughput_delta),
        sum(energy_usage_under_eclipse_delta),
        sum(power_draw_delta)
    )::asset_state as delta
FROM eventwise_asset_state_change as event_change, satellite
WHERE event_change.asset_id=satellite.id
    AND event_change.asset_type='satellite'::asset_type
    AND (storage_delta <> 0 OR throughput_delta <> 0)-- ignore cases where no change to the state
GROUP BY event_change.schedule_id, event_change.asset_type, event_change.asset_id, snapshot_time, storage_capacity; -- aggregate changes to the load made at the same time into one change

-- CREATE INDEX IF NOT EXISTS snapshot_time_index ON satellite_state_change (snapshot_time);
-- CREATE INDEX IF NOT EXISTS satellite_schedule_index ON satellite_state_change (schedule_id, satellite_id);
-- CREATE INDEX IF NOT EXISTS schedule_index ON satellite_state_change (schedule_id); -- useful when calculating average satellite utilization for example - you want events for all satellites within the same schedule


CREATE VIEW ground_station_state_change AS
SELECT event_change.schedule_id,
    event_change.asset_id, 
    event_change.asset_type,
    snapshot_time,
    default_asset_state() as delta -- TODO: fill in the state_delta
FROM eventwise_asset_state_change as event_change, ground_station
WHERE event_change.asset_id=ground_station.id
    AND event_change.asset_type='groundstation'::asset_type
GROUP BY event_change.schedule_id, event_change.asset_type, event_change.asset_id, snapshot_time;


CREATE TABLE IF NOT EXISTS state_checkpoint (
    id integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    schedule_id integer DEFAULT 0 REFERENCES schedule (id),
    asset_id integer REFERENCES asset (id),
    asset_type asset_type NOT NULL,
    checkpoint_time timestamptz NOT NULL,
    state asset_state NOT NULL DEFAULT default_asset_state(),
    delta_from_prev_chkpt asset_state NOT NULL DEFAULT default_asset_state(), -- cumulative delta of all the changes since the last checkpoint - basically how much has the state changed since the last checkpoint?
    peak_delta_from_prev_chkpt asset_state NOT NULL DEFAULT default_asset_state()-- peak state values since last checkpoint, offset from the state values at the last checkpoint. Used to see if we have exceeded the satellite's capacity since the last checkpoint, to know if we have to fix the schedule made there
);


-- just sample data for testing. You can delete anytime
INSERT INTO state_checkpoint (
    schedule_id, 
    asset_id, 
    asset_type, 
    checkpoint_time, 
    state, 
    delta_from_prev_chkpt, 
    peak_delta_from_prev_chkpt
) VALUES (
    (SELECT id FROM schedule ORDER BY id ASC LIMIT 1), -- first schedule_id
    (SELECT id FROM asset ORDER BY id ASC LIMIT 1), -- first asset_id
    'satellite'::asset_type, -- asset_type
    NOW(), -- checkpoint_time
    default_asset_state(),
    default_asset_state(),
    default_asset_state()
    -- (10.0, 20.0, 30.0, 0.0)::asset_state, -- state
    -- (5.0, 10.0, 15.0, 0.0)::asset_state, -- cumulative_change
    -- (2.0, 4.0, 6.0, 0.0)::asset_state -- peak_cumulative_change
);
