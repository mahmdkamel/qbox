-- Configuration table for container1 with nested hierarchy
container1_config = {
    initiator1 = {
        moduletype = "InitiatorTester";
        initiator_socket = {bind = "&router.target_socket"};
    };

    router = {
        moduletype = "router";
    };

    memory_a = {
        moduletype = "gs_memory";
        target_socket = {
            address = 0x40000000;
            size = 0x1000;
            bind = "&router.initiator_socket";
        };
    };

    memory_b = {
        moduletype = "gs_memory";
        target_socket = {
            address = 0x50000000;
            size = 0x1000;
            bind = "&router.initiator_socket";
        };
    };

    nested_container = {
        moduletype = "Container";

        initiator_nested = {
            moduletype = "InitiatorTester";
            initiator_socket = {bind = "&router_nested.target_socket"};
        };

        router_nested = {
            moduletype = "router";
        };

        memory_nested = {
            moduletype = "gs_memory";
            target_socket = {
                address = 0x60000000;
                size = 0x1000;
                bind = "&router_nested.initiator_socket";
            };
        };
    };

    sockets = {
        external_initiator_to_router = "&router.target_socket";
        router_to_external = "&router.initiator_socket";
    };
};

-- Configuration table for container2
container2_config = {
    initiator2 = {
        moduletype = "InitiatorTester";
        initiator_socket = {bind = "&router.target_socket"};
    };

    router = {
        moduletype = "router";
    };

    memory_x = {
        moduletype = "gs_memory";
        target_socket = {
            address = 0x70000000;
            size = 0x1000;
            bind = "&router.initiator_socket";
        };
    };

    memory_y = {
        moduletype = "gs_memory";
        target_socket = {
            address = 0x80000000;
            size = 0x1000;
            bind = "&router.initiator_socket";
        };
    };

    sockets = {
        external_initiator_to_router = "&router.target_socket";
        router_to_external = "&router.initiator_socket";
    };
};

-- Configuration table for an exported socket alias chain. Only the first
-- alias receives external address/bind parameters below; container_builder
-- must forward those parameters through second_hop to router.target_socket.
container3_config = {
    initiator3 = {
        moduletype = "InitiatorTester";
        initiator_socket = {bind = "&router.target_socket"};
    };

    router = {
        moduletype = "router";
    };

    memory_z = {
        moduletype = "gs_memory";
        target_socket = {
            address = 0x90000000;
            size = 0x1000;
            bind = "&router.initiator_socket";
        };
    };

    sockets = {
        first_hop = "&second_hop";
        second_hop = "&router.target_socket";
    };
};

-- Two exported aliases converge on shared_hop before reaching the router.
-- The second alias must replace the first alias's address and size.
container4_config = {
    initiator4 = {
        moduletype = "InitiatorTester";
        initiator_socket = {bind = "&router.target_socket"};
    };

    router = {
        moduletype = "router";
    };

    memory = {
        moduletype = "gs_memory";
        target_socket = {
            address = 0xC0000000;
            size = 0x1000;
            bind = "&router.initiator_socket";
        };
    };

    sockets = {
        first_hop = "&shared_hop";
        second_hop = "&shared_hop";
        shared_hop = "&router.target_socket";
    };
};

AllTests = {
    platform = {
        moduletype = "Container";

        initiator = {
            moduletype = "InitiatorTester";
            initiator_socket = {bind = "&router_main.target_socket"};
        };

        router_main = {
            moduletype = "router";
        };

        memory1 = {
            moduletype = "gs_memory";
            target_socket = {
                address = 0x10000000;
                size = 0x1000;
                bind = "&router_main.initiator_socket";
            };
        };

        memory2 = {
            moduletype = "gs_memory";
            target_socket = {
                address = 0x20000000;
                size = 0x1000;
                bind = "&router_main.initiator_socket";
            };
        };

        memory3 = {
            moduletype = "gs_memory";
            target_socket = {
                address = 0x30000000;
                size = 0x1000;
                bind = "&router_main.initiator_socket";
            };
        };

        container1 = {
            moduletype = "container_builder";
            config = container1_config;
        };

        container2 = {
            moduletype = "container_builder";
            config = container2_config;
        };

        container3 = {
            moduletype = "container_builder";
            config = container3_config;
            first_hop = {
                address = 0x90000000;
                size = 0x1000;
            };
        };

        chain_bind_probe = {
            bind = "&platform.container3.first_hop";
        };

        container4 = {
            moduletype = "container_builder";
            config = container4_config;
            first_hop = {
                address = 0xA0000000;
                size = 0x1000;
            };
            second_hop = {
                address = 0xB0000000;
                size = 0x2000;
            };
        };
    };
}
