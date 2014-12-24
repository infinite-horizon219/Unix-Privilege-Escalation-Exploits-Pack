diff -Nru linux-source-2.6.28/arch/x86/Kconfig linux-source-2.6.28-gs-bfq/arch/x86/Kconfig
--- linux-source-2.6.28/arch/x86/Kconfig	2009-04-17 03:57:42.000000000 +0200
+++ linux-source-2.6.28-gs-bfq/arch/x86/Kconfig	2009-04-25 09:44:01.000000000 +0200
@@ -629,6 +629,14 @@
 
 source "kernel/Kconfig.preempt"
 
+config GENERIC_SCHEDULER
+	bool "Generic scheduling support"
+	depends on !SMP && !RT_GROUP_SCHED
+	help
+	  The Generic Scheduler Patch for the Linux kernel, allowing loadable
+	  modules to be notified of scheduling related events, e.g., block,
+	  unblock, suspension, continuation, creation and destruction of tasks.
+
 config X86_UP_APIC
 	bool "Local APIC support on uniprocessors"
 	depends on X86_32 && !SMP && !(X86_VOYAGER || X86_GENERICARCH)
diff -Nru linux-source-2.6.28/block/bfq-cgroup.c linux-source-2.6.28-gs-bfq/block/bfq-cgroup.c
--- linux-source-2.6.28/block/bfq-cgroup.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-source-2.6.28-gs-bfq/block/bfq-cgroup.c	2009-04-28 12:01:06.000000000 +0200
@@ -0,0 +1,743 @@
+/*
+ * BFQ: CGROUPS support.
+ *
+ * Based on ideas and code from CFQ:
+ * Copyright (C) 2003 Jens Axboe <axboe@kernel.dk>
+ *
+ * Copyright (C) 2008 Fabio Checconi <fabio@gandalf.sssup.it>
+ *		      Paolo Valente <paolo.valente@unimore.it>
+ */
+
+#ifdef CONFIG_CGROUP_BFQIO
+static struct bfqio_cgroup bfqio_root_cgroup = {
+	.ioprio = BFQ_DEFAULT_GRP_IOPRIO,
+	.ioprio_class = BFQ_DEFAULT_GRP_CLASS,
+};
+
+static inline void bfq_init_entity(struct bfq_entity *entity,
+				   struct bfq_group *bfqg)
+{
+	entity->ioprio = entity->new_ioprio;
+	entity->ioprio_class = entity->new_ioprio_class;
+	entity->parent = bfqg->my_entity;
+	entity->sched_data = &bfqg->sched_data;
+}
+
+static struct bfqio_cgroup *cgroup_to_bfqio(struct cgroup *cgroup)
+{
+	return container_of(cgroup_subsys_state(cgroup, bfqio_subsys_id),
+			    struct bfqio_cgroup, css);
+}
+
+/*
+ * Search the bfq_group for bfqd into the hash table (by now only a list)
+ * of bgrp.  Must be called under rcu_read_lock().
+ */
+static struct bfq_group *bfqio_lookup_group(struct bfqio_cgroup *bgrp,
+					    struct bfq_data *bfqd)
+{
+	struct bfq_group *bfqg;
+	struct hlist_node *n;
+	void *key;
+
+	hlist_for_each_entry_rcu(bfqg, n, &bgrp->group_data, group_node) {
+		key = rcu_dereference(bfqg->bfqd);
+		if (key == bfqd)
+			return bfqg;
+	}
+
+	return NULL;
+}
+
+static inline void bfq_group_init_entity(struct bfqio_cgroup *bgrp,
+					 struct bfq_group *bfqg)
+{
+	struct bfq_entity *entity = &bfqg->entity;
+
+	entity->ioprio = entity->new_ioprio = bgrp->ioprio;
+	entity->ioprio_class = entity->new_ioprio_class = bgrp->ioprio_class;
+	entity->ioprio_changed = 1;
+	entity->my_sched_data = &bfqg->sched_data;
+}
+
+static inline void bfq_group_set_parent(struct bfq_group *bfqg,
+					struct bfq_group *parent)
+{
+	struct bfq_entity *entity;
+
+	BUG_ON(parent == NULL);
+	BUG_ON(bfqg == NULL);
+
+	entity = &bfqg->entity;
+	entity->parent = parent->my_entity;
+	entity->sched_data = &parent->sched_data;
+}
+
+/**
+ * bfq_group_chain_alloc - allocate a chain of groups.
+ * @bfqd: queue descriptor.
+ * @cgroup: the leaf cgroup this chain starts from.
+ *
+ * Allocate a chain of groups starting from the one belonging to
+ * @cgroup up to the root cgroup.  Stop if a cgroup on the chain
+ * to the root has already an allocated group on @bfqd.
+ */
+static struct bfq_group *bfq_group_chain_alloc(struct bfq_data *bfqd,
+					       struct cgroup *cgroup)
+{
+	struct bfqio_cgroup *bgrp;
+	struct bfq_group *bfqg, *prev = NULL, *leaf = NULL;
+
+	for (; cgroup != NULL; cgroup = cgroup->parent) {
+		bgrp = cgroup_to_bfqio(cgroup);
+
+		bfqg = bfqio_lookup_group(bgrp, bfqd);
+		if (bfqg != NULL) {
+			/*
+			 * All the cgroups in the path from there to the
+			 * root must have a bfq_group for bfqd, so we don't
+			 * need any more allocations.
+			 */
+			break;
+		}
+
+		bfqg = kzalloc(sizeof(*bfqg), GFP_ATOMIC);
+		if (bfqg == NULL)
+			goto cleanup;
+
+		bfq_group_init_entity(bgrp, bfqg);
+		bfqg->my_entity = &bfqg->entity;
+
+		if (leaf == NULL) {
+			leaf = bfqg;
+			prev = leaf;
+		} else {
+			bfq_group_set_parent(prev, bfqg);
+			/*
+			 * Build a list of allocated nodes using the bfqd
+			 * filed, that is still unused and will be initialized
+			 * only after the node will be connected.
+			 */
+			prev->bfqd = bfqg;
+			prev = bfqg;
+		}
+	}
+
+	return leaf;
+
+cleanup:
+	while (leaf != NULL) {
+		prev = leaf;
+		leaf = leaf->bfqd;
+		kfree(prev);
+	}
+
+	return NULL;
+}
+
+/**
+ * bfq_group_chain_link - link an allocatd group chain to a cgroup hierarchy.
+ * @bfqd: the queue descriptor.
+ * @cgroup: the leaf cgroup to start from.
+ * @leaf: the leaf group (to be associated to @cgroup).
+ *
+ * Try to link a chain of groups to a cgroup hierarchy, connecting the
+ * nodes bottom-up, so we can be sure that when we find a cgroup in the
+ * hierarchy that already as a group associated to @bfqd all the nodes
+ * in the path to the root cgroup have one too.
+ *
+ * On locking: the queue lock protects the hierarchy (there is a hierarchy
+ * per device) while the bfqio_cgroup lock protects the list of groups
+ * belonging to the same cgroup.
+ */
+static void bfq_group_chain_link(struct bfq_data *bfqd, struct cgroup *cgroup,
+				 struct bfq_group *leaf)
+{
+	struct bfqio_cgroup *bgrp;
+	struct bfq_group *bfqg, *next, *prev = NULL;
+	unsigned long flags;
+
+	assert_spin_locked(bfqd->queue->queue_lock);
+
+	for (; cgroup != NULL && leaf != NULL; cgroup = cgroup->parent) {
+		bgrp = cgroup_to_bfqio(cgroup);
+		next = leaf->bfqd;
+
+		bfqg = bfqio_lookup_group(bgrp, bfqd);
+		BUG_ON(bfqg != NULL);
+
+		spin_lock_irqsave(&bgrp->lock, flags);
+
+		rcu_assign_pointer(leaf->bfqd, bfqd);
+		hlist_add_head_rcu(&leaf->group_node, &bgrp->group_data);
+		hlist_add_head(&leaf->bfqd_node, &bfqd->group_list);
+
+		spin_unlock_irqrestore(&bgrp->lock, flags);
+
+		prev = leaf;
+		leaf = next;
+	}
+
+	BUG_ON(cgroup == NULL && leaf != NULL);
+	if (cgroup != NULL && prev != NULL) {
+		bgrp = cgroup_to_bfqio(cgroup);
+		bfqg = bfqio_lookup_group(bgrp, bfqd);
+		bfq_group_set_parent(prev, bfqg);
+	}
+}
+
+/**
+ * bfq_find_alloc_group - return the group associated to @bfqd in @cgroup.
+ * @bfqd: queue descriptor.
+ * @cgroup: cgroup being searched for.
+ *
+ * Return a group associated to @bfqd in @cgroup, allocating one if
+ * necessary.  When a group is returned all the cgroups in the path
+ * to the root have a group associated to @bfqd.
+ *
+ * If the allocation fails, return the root group: this breaks guarantees
+ * but is a safe fallbak.  If this loss becames a problem it can be
+ * mitigated using the equivalent weight (given by the product of the
+ * weights of the groups in the path from @group to the root) in the
+ * root scheduler.
+ *
+ * We allocate all the missing nodes in the path from the leaf cgroup
+ * to the root and we connect the nodes only after all the allocations
+ * have been successful.
+ */
+static struct bfq_group *bfq_find_alloc_group(struct bfq_data *bfqd,
+					      struct cgroup *cgroup)
+{
+	struct bfqio_cgroup *bgrp = cgroup_to_bfqio(cgroup);
+	struct bfq_group *bfqg;
+
+	bfqg = bfqio_lookup_group(bgrp, bfqd);
+	if (bfqg != NULL)
+		return bfqg;
+
+	bfqg = bfq_group_chain_alloc(bfqd, cgroup);
+	if (bfqg != NULL)
+		bfq_group_chain_link(bfqd, cgroup, bfqg);
+	else
+		bfqg = bfqd->root_group;
+
+	return bfqg;
+}
+
+/**
+ * bfq_bfqq_move - migrate @bfqq to @bfqg.
+ * @bfqd: queue descriptor.
+ * @bfqq: the queue to move.
+ * @entity: @bfqq's entity.
+ * @bfqg: the group to move to.
+ *
+ * Move @bfqq to @bfqg, deactivating it from its old group and reactivating
+ * it on the new one.  Avoid putting the entity on the old group idle tree.
+ *
+ * Must be called under the queue lock; the cgroup owning @bfqg must
+ * not disappear (by now this just means that we are called under
+ * rcu_read_lock()).
+ */
+static void bfq_bfqq_move(struct bfq_data *bfqd, struct bfq_queue *bfqq,
+			  struct bfq_entity *entity, struct bfq_group *bfqg)
+{
+	int busy, resume;
+
+	busy = bfq_bfqq_busy(bfqq);
+	resume = !RB_EMPTY_ROOT(&bfqq->sort_list);
+
+	BUG_ON(resume && !entity->on_st);
+	BUG_ON(busy && !resume && entity->on_st && bfqq != bfqd->active_queue);
+
+	if (busy) {
+		BUG_ON(atomic_read(&bfqq->ref) < 2);
+
+		if (!resume)
+			bfq_del_bfqq_busy(bfqd, bfqq, 0);
+		else
+			bfq_deactivate_bfqq(bfqd, bfqq, 0);
+	}
+
+	/*
+	 * Here we use a reference to bfqg.  We don't need a refcounter
+	 * as the cgroup reference will not be dropped, so that its
+	 * destroy() callback will not be invoked.
+	 */
+	entity->parent = bfqg->my_entity;
+	entity->sched_data = &bfqg->sched_data;
+
+	if (busy && resume)
+		bfq_activate_bfqq(bfqd, bfqq);
+}
+
+/**
+ * __bfq_cic_change_cgroup - move @cic to @cgroup.
+ * @bfqd: the queue descriptor.
+ * @cic: the cic to move.
+ * @cgroup: the cgroup to move to.
+ *
+ * Move cic to cgroup, assuming that bfqd->queue is locked; the caller
+ * has to make sure that the reference to cgroup is valid across the call.
+ *
+ * NOTE: an alternative approach might have been to store the current
+ * cgroup in bfqq and getting a reference to it, reducing the lookup
+ * time here, at the price of slightly more complex code.
+ */
+static struct bfq_group *__bfq_cic_change_cgroup(struct bfq_data *bfqd,
+						 struct cfq_io_context *cic,
+						 struct cgroup *cgroup)
+{
+	struct bfq_queue *async_bfqq = cic_to_bfqq(cic, 0);
+	struct bfq_queue *sync_bfqq = cic_to_bfqq(cic, 1);
+	struct bfq_entity *entity;
+	struct bfq_group *bfqg;
+	struct bfqio_cgroup *bgrp;
+
+	bgrp = cgroup_to_bfqio(cgroup);
+
+	bfqg = bfq_find_alloc_group(bfqd, cgroup);
+	if (async_bfqq != NULL) {
+		entity = &async_bfqq->entity;
+
+		if (entity->sched_data != &bfqg->sched_data) {
+			cic_set_bfqq(cic, NULL, 0);
+			bfq_put_queue(async_bfqq);
+		}
+	}
+
+	if (sync_bfqq != NULL) {
+		entity = &sync_bfqq->entity;
+		if (entity->sched_data != &bfqg->sched_data)
+			bfq_bfqq_move(bfqd, sync_bfqq, entity, bfqg);
+	}
+
+	return bfqg;
+}
+
+/**
+ * bfq_cic_change_cgroup - move @cic to @cgroup.
+ * @cic: the cic being migrated.
+ * @cgroup: the destination cgroup.
+ *
+ * When the task owning @cic is moved to @cgroup, @cic is immediately
+ * moved into its new parent group.
+ */
+static void bfq_cic_change_cgroup(struct cfq_io_context *cic,
+				  struct cgroup *cgroup)
+{
+	struct bfq_data *bfqd;
+	unsigned long uninitialized_var(flags);
+
+	bfqd = bfq_get_bfqd_locked(&cic->key, &flags);
+	if (bfqd != NULL) {
+		__bfq_cic_change_cgroup(bfqd, cic, cgroup);
+		bfq_put_bfqd_unlock(bfqd, &flags);
+	}
+}
+
+/**
+ * bfq_cic_update_cgroup - update the cgroup of @cic.
+ * @cic: the @cic to update.
+ *
+ * Make sure that @cic is enqueued in the cgroup of the current task.
+ * We need this in addition to moving cics during the cgroup attach
+ * phase because the task owning @cic could be at its first disk
+ * access or we may end up in the root cgroup as the result of a
+ * memory allocation failure and here we try to move to the right
+ * group.
+ *
+ * Must be called under the queue lock.  It is safe to use the returned
+ * value even after the rcu_read_unlock() as the migration/destruction
+ * paths act under the queue lock too.  IOW it is impossible to race with
+ * group migration/destruction and end up with an invalid group as:
+ *   a) here cgroup has not yet been destroyed, nor its destroy callback
+ *      has started execution, as current holds a reference to it,
+ *   b) if it is destroyed after rcu_read_unlock() [after current is
+ *      migrated to a different cgroup] its attach() callback will have
+ *      taken care of remove all the references to the old cgroup data.
+ */
+static struct bfq_group *bfq_cic_update_cgroup(struct cfq_io_context *cic)
+{
+	struct bfq_data *bfqd = cic->key;
+	struct bfq_group *bfqg;
+	struct cgroup *cgroup;
+
+	BUG_ON(bfqd == NULL);
+
+	rcu_read_lock();
+	cgroup = task_cgroup(current, bfqio_subsys_id);
+	bfqg = __bfq_cic_change_cgroup(bfqd, cic, cgroup);
+	rcu_read_unlock();
+
+	return bfqg;
+}
+
+/**
+ * bfq_flush_idle_tree - deactivate any entity on the idle tree of @st.
+ * @st: the service tree being flushed.
+ */
+static inline void bfq_flush_idle_tree(struct bfq_service_tree *st)
+{
+	struct bfq_entity *entity = st->first_idle;
+
+	for (; entity != NULL; entity = st->first_idle)
+		__bfq_deactivate_entity(entity, 0);
+}
+
+/**
+ * bfq_destroy_group - destroy @bfqg.
+ * @bgrp: the bfqio_cgroup containing @bfqg.
+ * @bfqg: the group being destroyed.
+ *
+ * Destroy @bfqg, making sure that it is not referenced from its parent.
+ */
+static void bfq_destroy_group(struct bfqio_cgroup *bgrp, struct bfq_group *bfqg)
+{
+	struct bfq_data *bfqd;
+	struct bfq_service_tree *st;
+	struct bfq_entity *entity = bfqg->my_entity;
+	unsigned long uninitialized_var(flags);
+	int i;
+
+	hlist_del(&bfqg->group_node);
+
+	/*
+	 * We may race with device destruction, take extra care when
+	 * dereferencing bfqg->bfqd.
+	 */
+	bfqd = bfq_get_bfqd_locked(&bfqg->bfqd, &flags);
+	if (bfqd != NULL) {
+		hlist_del(&bfqg->bfqd_node);
+		__bfq_deactivate_entity(entity, 0);
+		bfq_put_async_queues(bfqd, bfqg);
+		bfq_put_bfqd_unlock(bfqd, &flags);
+	}
+
+	for (i = 0; i < BFQ_IOPRIO_CLASSES; i++) {
+		st = bfqg->sched_data.service_tree + i;
+
+		/*
+		 * The idle tree may still contain bfq_queues belonging
+		 * to exited task because they never migrated to a different
+		 * cgroup from the one being destroyed now.  Noone else
+		 * can access them so it's safe to act without any lock.
+		 */
+		bfq_flush_idle_tree(st);
+
+		BUG_ON(!RB_EMPTY_ROOT(&st->active));
+		BUG_ON(!RB_EMPTY_ROOT(&st->idle));
+	}
+	BUG_ON(bfqg->sched_data.next_active != NULL);
+	BUG_ON(bfqg->sched_data.active_entity != NULL);
+	BUG_ON(entity->tree != NULL);
+
+	/*
+	 * No need to defer the kfree() to the end of the RCU grace
+	 * period: we are called from the destroy() callback of our
+	 * cgroup, so we can be sure that noone is a) still using
+	 * this cgroup or b) doing lookups in it.
+	 */
+	kfree(bfqg);
+}
+
+/**
+ * bfq_disconnect_groups - diconnect @bfqd from all its groups.
+ * @bfqd: the device descriptor being exited.
+ *
+ * When the device exits we just make sure that no lookup can return
+ * the now unused group structures.  They will be deallocated on cgroup
+ * destruction.
+ */
+static void bfq_disconnect_groups(struct bfq_data *bfqd)
+{
+	struct hlist_node *pos, *n;
+	struct bfq_group *bfqg;
+
+	hlist_for_each_entry_safe(bfqg, pos, n, &bfqd->group_list, bfqd_node) {
+		hlist_del(&bfqg->bfqd_node);
+
+		__bfq_deactivate_entity(bfqg->my_entity, 0);
+
+		/*
+		 * Don't remove from the group hash, just set an
+		 * invalid key.  No lookups can race with the
+		 * assignment as bfqd is being destroyed; this
+		 * implies also that new elements cannot be added
+		 * to the list.
+		 */
+		rcu_assign_pointer(bfqg->bfqd, NULL);
+		bfq_put_async_queues(bfqd, bfqg);
+	}
+}
+
+static inline void bfq_free_root_group(struct bfq_data *bfqd)
+{
+	struct bfqio_cgroup *bgrp = &bfqio_root_cgroup;
+	struct bfq_group *bfqg = bfqd->root_group;
+
+	spin_lock_irq(&bgrp->lock);
+	hlist_del_rcu(&bfqg->group_node);
+	spin_unlock_irq(&bgrp->lock);
+
+	/*
+	 * No need to synchronize_rcu() here: since the device is gone
+	 * there cannot be any read-side access to its root_group.
+	 */
+	kfree(bfqg);
+}
+
+static struct bfq_group *bfq_alloc_root_group(struct bfq_data *bfqd, int node)
+{
+	struct bfq_group *bfqg;
+	struct bfqio_cgroup *bgrp;
+	int i;
+
+	bfqg = kmalloc_node(sizeof(*bfqg), GFP_KERNEL | __GFP_ZERO, node);
+	if (bfqg == NULL)
+		return NULL;
+
+	bfqg->entity.parent = NULL;
+	for (i = 0; i < BFQ_IOPRIO_CLASSES; i++)
+		bfqg->sched_data.service_tree[i] = BFQ_SERVICE_TREE_INIT;
+
+	bgrp = &bfqio_root_cgroup;
+	spin_lock_irq(&bgrp->lock);
+	rcu_assign_pointer(bfqg->bfqd, bfqd);
+	hlist_add_head_rcu(&bfqg->group_node, &bgrp->group_data);
+	spin_unlock_irq(&bgrp->lock);
+
+	return bfqg;
+}
+
+#define SHOW_FUNCTION(__VAR)						\
+static u64 bfqio_cgroup_##__VAR##_read(struct cgroup *cgroup,		\
+				       struct cftype *cftype)		\
+{									\
+	struct bfqio_cgroup *bgrp;					\
+	u64 ret;							\
+									\
+	if (!cgroup_lock_live_group(cgroup))				\
+		return -ENODEV;						\
+									\
+	bgrp = cgroup_to_bfqio(cgroup);					\
+	spin_lock_irq(&bgrp->lock);					\
+	ret = bgrp->__VAR;						\
+	spin_unlock_irq(&bgrp->lock);					\
+									\
+	cgroup_unlock();						\
+									\
+	return ret;							\
+}
+
+SHOW_FUNCTION(ioprio);
+SHOW_FUNCTION(ioprio_class);
+#undef SHOW_FUNCTION
+
+#define STORE_FUNCTION(__VAR, __MIN, __MAX)				\
+static int bfqio_cgroup_##__VAR##_write(struct cgroup *cgroup,		\
+					struct cftype *cftype,		\
+					u64 val)			\
+{									\
+	struct bfqio_cgroup *bgrp;					\
+	struct bfq_group *bfqg;						\
+	struct hlist_node *n;						\
+									\
+	if (val < (__MIN) || val > (__MAX))				\
+		return -EINVAL;						\
+									\
+	if (!cgroup_lock_live_group(cgroup))				\
+		return -ENODEV;						\
+									\
+	bgrp = cgroup_to_bfqio(cgroup);					\
+									\
+	spin_lock_irq(&bgrp->lock);					\
+	bgrp->__VAR = (unsigned char)val;				\
+	hlist_for_each_entry(bfqg, n, &bgrp->group_data, group_node) {	\
+		bfqg->entity.new_##__VAR = (unsigned char)val;		\
+		smp_wmb();						\
+		bfqg->entity.ioprio_changed = 1;			\
+	}								\
+	spin_unlock_irq(&bgrp->lock);					\
+									\
+	cgroup_unlock();						\
+									\
+	return 0;							\
+}
+
+STORE_FUNCTION(ioprio, 0, IOPRIO_BE_NR - 1);
+STORE_FUNCTION(ioprio_class, IOPRIO_CLASS_RT, IOPRIO_CLASS_IDLE);
+#undef STORE_FUNCTION
+
+static struct cftype bfqio_files[] = {
+	{
+		.name = "ioprio",
+		.read_u64 = bfqio_cgroup_ioprio_read,
+		.write_u64 = bfqio_cgroup_ioprio_write,
+	},
+	{
+		.name = "ioprio_class",
+		.read_u64 = bfqio_cgroup_ioprio_class_read,
+		.write_u64 = bfqio_cgroup_ioprio_class_write,
+	},
+};
+
+static int bfqio_populate(struct cgroup_subsys *subsys, struct cgroup *cgroup)
+{
+	return cgroup_add_files(cgroup, subsys, bfqio_files,
+				ARRAY_SIZE(bfqio_files));
+}
+
+static struct cgroup_subsys_state *bfqio_create(struct cgroup_subsys *subsys,
+						struct cgroup *cgroup)
+{
+	struct bfqio_cgroup *bgrp;
+
+	if (cgroup->parent != NULL) {
+		bgrp = kzalloc(sizeof(*bgrp), GFP_KERNEL);
+		if (bgrp == NULL)
+			return ERR_PTR(-ENOMEM);
+	} else
+		bgrp = &bfqio_root_cgroup;
+
+	spin_lock_init(&bgrp->lock);
+	INIT_HLIST_HEAD(&bgrp->group_data);
+	bgrp->ioprio = BFQ_DEFAULT_GRP_IOPRIO;
+	bgrp->ioprio_class = BFQ_DEFAULT_GRP_CLASS;
+
+	return &bgrp->css;
+}
+
+/*
+ * We cannot support shared io contexts, as we have no mean to support
+ * two tasks with the same ioc in two different groups without major rework
+ * of the main cic/bfqq data structures.  By now we allow a task to change
+ * its cgroup only if it's the only owner of its ioc; the drawback of this
+ * behavior is that a group containing a task that forked using CLONE_IO
+ * will not be destroyed until the tasks sharing the ioc die.
+ */
+static int bfqio_can_attach(struct cgroup_subsys *subsys, struct cgroup *cgroup,
+			    struct task_struct *tsk)
+{
+	struct io_context *ioc;
+	int ret = 0;
+
+	/* task_lock() is needed to avoid races with exit_io_context() */
+	task_lock(tsk);
+	ioc = tsk->io_context;
+	if (ioc != NULL && atomic_read(&ioc->nr_tasks) > 1)
+		/*
+		 * ioc == NULL means that the task is either too young or
+		 * exiting: if it has still no ioc the ioc can't be shared,
+		 * if the task is exiting the attach will fail anyway, no
+		 * matter what we return here.
+		 */
+		ret = -EINVAL;
+	task_unlock(tsk);
+
+	return ret;
+}
+
+static void bfqio_attach(struct cgroup_subsys *subsys, struct cgroup *cgroup,
+			 struct cgroup *prev, struct task_struct *tsk)
+{
+	struct io_context *ioc;
+	struct cfq_io_context *cic;
+	struct hlist_node *n;
+
+	task_lock(tsk);
+	ioc = tsk->io_context;
+	if (ioc != NULL) {
+		BUG_ON(atomic_read(&ioc->refcount) == 0);
+		atomic_inc(&ioc->refcount);
+	}
+	task_unlock(tsk);
+
+	if (ioc == NULL)
+		return;
+
+	rcu_read_lock();
+	hlist_for_each_entry_rcu(cic, n, &ioc->bfq_cic_list, cic_list)
+		bfq_cic_change_cgroup(cic, cgroup);
+	rcu_read_unlock();
+
+	put_io_context(ioc);
+}
+
+static void bfqio_destroy(struct cgroup_subsys *subsys, struct cgroup *cgroup)
+{
+	struct bfqio_cgroup *bgrp = cgroup_to_bfqio(cgroup);
+	struct hlist_node *n, *tmp;
+	struct bfq_group *bfqg;
+
+	/*
+	 * Since we are destroying the cgroup, there are no more tasks
+	 * referencing it, and all the RCU grace periods that may have
+	 * referenced it are ended (as the destruction of the parent
+	 * cgroup is RCU-safe); bgrp->group_data will not be accessed by
+	 * anything else and we don't need any synchronization.
+	 */
+	hlist_for_each_entry_safe(bfqg, n, tmp, &bgrp->group_data, group_node)
+		bfq_destroy_group(bgrp, bfqg);
+
+	BUG_ON(!hlist_empty(&bgrp->group_data));
+
+	kfree(bgrp);
+}
+
+struct cgroup_subsys bfqio_subsys = {
+	.name = "bfqio",
+	.create = bfqio_create,
+	.can_attach = bfqio_can_attach,
+	.attach = bfqio_attach,
+	.destroy = bfqio_destroy,
+	.populate = bfqio_populate,
+	.subsys_id = bfqio_subsys_id,
+};
+#else
+static inline void bfq_init_entity(struct bfq_entity *entity,
+				   struct bfq_group *bfqg)
+{
+	entity->ioprio = entity->new_ioprio;
+	entity->ioprio_class = entity->new_ioprio_class;
+	entity->sched_data = &bfqg->sched_data;
+}
+
+static inline struct bfq_group *
+bfq_cic_update_cgroup(struct cfq_io_context *cic)
+{
+	struct bfq_data *bfqd = cic->key;
+	return bfqd->root_group;
+}
+
+static inline void bfq_bfqq_move(struct bfq_data *bfqd,
+				 struct bfq_queue *bfqq,
+				 struct bfq_entity *entity,
+				 struct bfq_group *bfqg)
+{
+}
+
+static inline void bfq_disconnect_groups(struct bfq_data *bfqd)
+{
+	bfq_put_async_queues(bfqd, bfqd->root_group);
+}
+
+static inline void bfq_free_root_group(struct bfq_data *bfqd)
+{
+	kfree(bfqd->root_group);
+}
+
+static struct bfq_group *bfq_alloc_root_group(struct bfq_data *bfqd, int node)
+{
+	struct bfq_group *bfqg;
+	int i;
+
+	bfqg = kmalloc_node(sizeof(*bfqg), GFP_KERNEL | __GFP_ZERO, node);
+	if (bfqg == NULL)
+		return NULL;
+
+	for (i = 0; i < BFQ_IOPRIO_CLASSES; i++)
+		bfqg->sched_data.service_tree[i] = BFQ_SERVICE_TREE_INIT;
+
+	return bfqg;
+}
+#endif
diff -Nru linux-source-2.6.28/block/bfq.h linux-source-2.6.28-gs-bfq/block/bfq.h
--- linux-source-2.6.28/block/bfq.h	1970-01-01 01:00:00.000000000 +0100
+++ linux-source-2.6.28-gs-bfq/block/bfq.h	2009-04-28 12:01:06.000000000 +0200
@@ -0,0 +1,514 @@
+/*
+ * BFQ: data structures and common functions prototypes.
+ *
+ * Based on ideas and code from CFQ:
+ * Copyright (C) 2003 Jens Axboe <axboe@kernel.dk>
+ *
+ * Copyright (C) 2008 Fabio Checconi <fabio@gandalf.sssup.it>
+ *		      Paolo Valente <paolo.valente@unimore.it>
+ */
+
+#ifndef _BFQ_H
+#define _BFQ_H
+
+#include <linux/blktrace_api.h>
+#include <linux/hrtimer.h>
+#include <linux/ioprio.h>
+#include <linux/rbtree.h>
+
+#define ASYNC			0
+#define SYNC			1
+
+#define BFQ_IOPRIO_CLASSES	3
+
+#define BFQ_DEFAULT_GRP_IOPRIO	4
+#define BFQ_DEFAULT_GRP_CLASS	IOPRIO_CLASS_BE
+
+typedef u64 bfq_timestamp_t;
+typedef unsigned long bfq_weight_t;
+typedef unsigned long bfq_service_t;
+
+struct bfq_entity;
+
+/**
+ * struct bfq_service_tree - per ioprio_class service tree.
+ * @active: tree for active entities (i.e., those backlogged).
+ * @idle: tree for idle entities (i.e., those not backlogged, with V <= F_i).
+ * @first_idle: idle entity with minimum F_i.
+ * @last_idle: idle entity with maximum F_i.
+ * @vtime: scheduler virtual time.
+ * @wsum: scheduler weight sum; active and idle entities contribute to it.
+ *
+ * Each service tree represents a B-WF2Q+ scheduler on its own.  Each
+ * ioprio_class has its own independent scheduler, and so its own
+ * bfq_service_tree.  All the fields are protected by the queue lock
+ * of the containing bfqd.
+ */
+struct bfq_service_tree {
+	struct rb_root active;
+	struct rb_root idle;
+
+	struct bfq_entity *first_idle;
+	struct bfq_entity *last_idle;
+
+	bfq_timestamp_t vtime;
+	bfq_weight_t wsum;
+};
+
+/**
+ * struct bfq_sched_data - multi-class scheduler.
+ * @active_entity: entity under service.
+ * @next_active: head-of-the-line entity in the scheduler.
+ * @service_tree: array of service trees, one per ioprio_class.
+ *
+ * bfq_sched_data is the basic scheduler queue.  It supports three
+ * ioprio_classes, and can be used either as a toplevel queue or as
+ * an intermediate queue on a hierarchical setup.
+ * @next_active points to the active entity of the sched_data service
+ * trees that will be scheduled next.
+ *
+ * The supported ioprio_classes are the same as in CFQ, in descending
+ * priority order, IOPRIO_CLASS_RT, IOPRIO_CLASS_BE, IOPRIO_CLASS_IDLE.
+ * Requests from higher priority queues are served before all the
+ * requests from lower priority queues; among requests of the same
+ * queue requests are served according to B-WF2Q+.
+ * All the fields are protected by the queue lock of the containing bfqd.
+ */
+struct bfq_sched_data {
+	struct bfq_entity *active_entity;
+	struct bfq_entity *next_active;
+	struct bfq_service_tree service_tree[BFQ_IOPRIO_CLASSES];
+};
+
+/**
+ * struct bfq_entity - schedulable entity.
+ * @rb_node: service_tree member.
+ * @on_st: flag, true if the entity is on a tree (either the active or
+ *         the idle one of its service_tree).
+ * @finish: B-WF2Q+ finish timestamp (aka F_i).
+ * @start: B-WF2Q+ start timestamp (aka S_i).
+ * @tree: tree the entity is enqueued into; %NULL if not on a tree.
+ * @min_start: minimum start time of the (active) subtree rooted at
+ *             this entity; used for O(log N) lookups into active trees.
+ * @service: service received during the last round of service.
+ * @budget: budget used to calculate F_i; F_i = S_i + @budget / @weight.
+ * @weight: weight of the queue, calculated as IOPRIO_BE_NR - @ioprio.
+ * @parent: parent entity, for hierarchical scheduling.
+ * @my_sched_data: for non-leaf nodes in the cgroup hierarchy, the
+ *                 associated scheduler queue, %NULL on leaf nodes.
+ * @sched_data: the scheduler queue this entity belongs to.
+ * @ioprio: the ioprio in use.
+ * @new_ioprio: when an ioprio change is requested, the new ioprio value
+ * @ioprio_class: the ioprio_class in use.
+ * @new_ioprio_class: when an ioprio_class change is requested, the new
+ *                    ioprio_class value.
+ * @ioprio_changed: flag, true when the user requested an ioprio or
+ *                  ioprio_class change.
+ *
+ * A bfq_entity is used to represent either a bfq_queue (leaf node in the
+ * cgroup hierarchy) or a bfq_group into the upper level scheduler.  Each
+ * entity belongs to the sched_data of the parent group in the cgroup
+ * hierarchy.  Non-leaf entities have also their own sched_data, stored
+ * in @my_sched_data.
+ *
+ * Each entity stores independently its priority values; this would allow
+ * different weights on different devices, but this functionality is not
+ * exported to userspace by now.  Priorities are updated lazily, first
+ * storing the new values into the new_* fields, then setting the
+ * @ioprio_changed flag.  As soon as there is a transition in the entity
+ * state that allows the priority update to take place the effective and
+ * the requested priority values are synchronized.
+ *
+ * The weight value is calculated from the ioprio to export the same
+ * interface as CFQ.  When dealing with ``well-behaved'' queues (i.e.,
+ * queues that do not spend too much time to consume their budget and
+ * have true sequential behavior, and when there are no external factors
+ * breaking anticipation) the relative weights at each level of the
+ * cgroups hierarchy should be guaranteed.
+ * All the fields are protected by the queue lock of the containing bfqd.
+ */
+struct bfq_entity {
+	struct rb_node rb_node;
+
+	int on_st;
+
+	bfq_timestamp_t finish;
+	bfq_timestamp_t start;
+
+	struct rb_root *tree;
+
+	bfq_timestamp_t min_start;
+
+	bfq_service_t service, budget;
+	bfq_weight_t weight;
+
+	struct bfq_entity *parent;
+
+	struct bfq_sched_data *my_sched_data;
+	struct bfq_sched_data *sched_data;
+
+	unsigned short ioprio, new_ioprio;
+	unsigned short ioprio_class, new_ioprio_class;
+
+	int ioprio_changed;
+};
+
+struct bfq_group;
+
+/**
+ * struct bfq_data - per device data structure.
+ * @queue: request queue for the managed device.
+ * @root_group: root bfq_group for the device.
+ * @busy_queues: number of bfq_queues containing requests (including the
+ *		 queue under service, even if it is idling).
+ * @queued: number of queued requests.
+ * @rq_in_driver: number of requests dispatched and waiting for completion.
+ * @sync_flight: number of sync requests in the driver.
+ * @max_rq_in_driver: max number of reqs in driver in the last @hw_tag_samples
+ *		      completed requests .
+ * @hw_tag_samples: nr of samples used to calculate hw_tag.
+ * @hw_tag: flag set to one if the driver is showing a queueing behavior.
+ * @idle_slice_timer: timer set when idling for the next sequential request
+ *                    from the queue under service.
+ * @unplug_work: delayed work to restart dispatching on the request queue.
+ * @active_queue: bfq_queue under service.
+ * @active_cic: cfq_io_context (cic) associated with the @active_queue.
+ * @last_position: on-disk position of the last served request.
+ * @last_budget_start: beginning of the last budget.
+ * @last_idling_start: beginning of the last idle slice.
+ * @peak_rate: peak transfer rate observed for a budget.
+ * @peak_rate_samples: number of samples used to calculate @peak_rate.
+ * @bfq_max_budget: maximum budget allotted to a bfq_queue before rescheduling.
+ * @cic_list: list of all the cics active on the bfq_data device.
+ * @group_list: list of all the bfq_groups active on the device.
+ * @active_list: list of all the bfq_queues active on the device.
+ * @idle_list: list of all the bfq_queues idle on the device.
+ * @bfq_quantum: max number of requests dispatched per dispatch round.
+ * @bfq_fifo_expire: timeout for async/sync requests; when it expires
+ *                   requests are served in fifo order.
+ * @bfq_back_penalty: weight of backward seeks wrt forward ones.
+ * @bfq_back_max: maximum allowed backward seek.
+ * @bfq_slice_idle: maximum idling time.
+ * @bfq_user_max_budget: user-configured max budget value (0 for auto-tuning).
+ * @bfq_max_budget_async_rq: maximum budget (in nr of requests) allotted to
+ *                           async queues.
+ * @bfq_timeout: timeout for bfq_queues to consume their budget; used to
+ *               to prevent seeky queues to impose long latencies to well
+ *               behaved ones (this also implies that seeky queues cannot
+ *               receive guarantees in the service domain; after a timeout
+ *               they are charged for the whole allocated budget, to try
+ *               to preserve a behavior reasonably fair among them, but
+ *               without service-domain guarantees).
+ *
+ * All the fields are protected by the @queue lock.
+ */
+struct bfq_data {
+	struct request_queue *queue;
+
+	struct bfq_group *root_group;
+
+	int busy_queues;
+	int queued;
+	int rq_in_driver;
+	int sync_flight;
+
+	int max_rq_in_driver;
+	int hw_tag_samples;
+	int hw_tag;
+
+	struct timer_list idle_slice_timer;
+	struct work_struct unplug_work;
+
+	struct bfq_queue *active_queue;
+	struct cfq_io_context *active_cic;
+
+	sector_t last_position;
+
+	ktime_t last_budget_start;
+	ktime_t last_idling_start;
+	int peak_rate_samples;
+	u64 peak_rate;
+	bfq_service_t bfq_max_budget;
+
+	struct list_head cic_list;
+	struct hlist_head group_list;
+	struct list_head active_list;
+	struct list_head idle_list;
+
+	unsigned int bfq_quantum;
+	unsigned int bfq_fifo_expire[2];
+	unsigned int bfq_back_penalty;
+	unsigned int bfq_back_max;
+	unsigned int bfq_slice_idle;
+
+	unsigned int bfq_user_max_budget;
+	unsigned int bfq_max_budget_async_rq;
+	unsigned int bfq_timeout[2];
+};
+
+/**
+ * struct bfq_queue - leaf schedulable entity.
+ * @ref: reference counter.
+ * @bfqd: parent bfq_data.
+ * @sort_list: sorted list of pending requests.
+ * @next_rq: if fifo isn't expired, next request to serve.
+ * @queued: nr of requests queued in @sort_list.
+ * @allocated: currently allocated requests.
+ * @meta_pending: pending metadata requests.
+ * @fifo: fifo list of requests in sort_list.
+ * @entity: entity representing this queue in the scheduler.
+ * @max_budget: maximum budget allowed from the feedback mechanism.
+ * @budget_timeout: budget expiration (in jiffies).
+ * @dispatched: number of requests on the dispatch list or inside driver.
+ * @budgets_assigned: number of budgets assigned.
+ * @org_ioprio: saved ioprio during boosted periods.
+ * @org_ioprio_class: saved ioprio_class during boosted periods.
+ * @flags: status flags.
+ * @bfqq_list: node for active/idle bfqq list inside our bfqd.
+ * @pid: pid of the process owning the queue, used for logging purposes.
+ *
+ * A bfq_queue is a leaf request queue; it can be associated to an io_context
+ * or more (if it is an async one).  @cgroup holds a reference to the
+ * cgroup, to be sure that it does not disappear while a bfqq still
+ * references it (mostly to avoid races between request issuing and task
+ * migration followed by cgroup distruction).
+ * All the fields are protected by the queue lock of the containing bfqd.
+ */
+struct bfq_queue {
+	atomic_t ref;
+	struct bfq_data *bfqd;
+
+	struct rb_root sort_list;
+	struct request *next_rq;
+	int queued[2];
+	int allocated[2];
+	int meta_pending;
+	struct list_head fifo;
+
+	struct bfq_entity entity;
+
+	bfq_service_t max_budget;
+	unsigned long budget_timeout;
+
+	int dispatched;
+	int budgets_assigned;
+
+	unsigned short org_ioprio;
+	unsigned short org_ioprio_class;
+
+	unsigned int flags;
+
+	struct list_head bfqq_list;
+
+	pid_t pid;
+};
+
+enum bfqq_state_flags {
+	BFQ_BFQQ_FLAG_busy = 0,		/* has requests or is under service */
+	BFQ_BFQQ_FLAG_wait_request,	/* waiting for a request */
+	BFQ_BFQQ_FLAG_must_alloc,	/* must be allowed rq alloc */
+	BFQ_BFQQ_FLAG_fifo_expire,	/* FIFO checked in this slice */
+	BFQ_BFQQ_FLAG_idle_window,	/* slice idling enabled */
+	BFQ_BFQQ_FLAG_prio_changed,	/* task priority has changed */
+	BFQ_BFQQ_FLAG_sync,		/* synchronous queue */
+	BFQ_BFQQ_FLAG_budget_new,	/* no completion with this budget */
+};
+
+#define BFQ_BFQQ_FNS(name)						\
+static inline void bfq_mark_bfqq_##name(struct bfq_queue *bfqq)		\
+{									\
+	(bfqq)->flags |= (1 << BFQ_BFQQ_FLAG_##name);			\
+}									\
+static inline void bfq_clear_bfqq_##name(struct bfq_queue *bfqq)	\
+{									\
+	(bfqq)->flags &= ~(1 << BFQ_BFQQ_FLAG_##name);			\
+}									\
+static inline int bfq_bfqq_##name(const struct bfq_queue *bfqq)		\
+{									\
+	return ((bfqq)->flags & (1 << BFQ_BFQQ_FLAG_##name)) != 0;	\
+}
+
+BFQ_BFQQ_FNS(busy);
+BFQ_BFQQ_FNS(wait_request);
+BFQ_BFQQ_FNS(must_alloc);
+BFQ_BFQQ_FNS(fifo_expire);
+BFQ_BFQQ_FNS(idle_window);
+BFQ_BFQQ_FNS(prio_changed);
+BFQ_BFQQ_FNS(sync);
+BFQ_BFQQ_FNS(budget_new);
+#undef BFQ_BFQQ_FNS
+
+/* Logging facilities. */
+#define bfq_log_bfqq(bfqd, bfqq, fmt, args...) \
+	blk_add_trace_msg((bfqd)->queue, "bfq%d " fmt, (bfqq)->pid, ##args)
+
+#define bfq_log(bfqd, fmt, args...) \
+	blk_add_trace_msg((bfqd)->queue, "bfq " fmt, ##args)
+
+/* Expiration reasons. */
+enum bfqq_expiration {
+	BFQ_BFQQ_TOO_IDLE = 0,		/* queue has been idling for too long */
+	BFQ_BFQQ_BUDGET_TIMEOUT,	/* budget took too long to be used */
+	BFQ_BFQQ_BUDGET_EXHAUSTED,	/* budget consumed */
+	BFQ_BFQQ_NO_MORE_REQUESTS,	/* the queue has no more requests */
+};
+
+#ifdef CONFIG_CGROUP_BFQIO
+/**
+ * struct bfq_group - per (device, cgroup) data structure.
+ * @entity: schedulable entity to insert into the parent group sched_data.
+ * @sched_data: own sched_data, to contain child entities (they may be
+ *              both bfq_queues and bfq_groups).
+ * @group_node: node to be inserted into the bfqio_cgroup->group_data
+ *              list of the containing cgroup's bfqio_cgroup.
+ * @bfqd_node: node to be inserted into the @bfqd->group_list list
+ *             of the groups active on the same device; used for cleanup.
+ * @bfqd: the bfq_data for the device this group acts upon.
+ * @async_bfqq: array of async queues for all the tasks belonging to
+ *              the group, one queue per ioprio value per ioprio_class,
+ *              except for the idle class that has only one queue.
+ * @async_idle_bfqq: async queue for the idle class (ioprio is ignored).
+ * @my_entity: pointer to @entity, %NULL for the toplevel group; used
+ *             to avoid too many special cases during group creation/migration.
+ *
+ * Each (device, cgroup) pair has its own bfq_group, i.e., for each cgroup
+ * there is a set of bfq_groups, each one collecting the lower-level
+ * entities belonging to the group that are acting on the same device.
+ *
+ * Locking works as follows:
+ *    o @group_node is protected by the bfqio_cgroup lock, and is accessed
+ *      via RCU from its readers.
+ *    o @bfqd is protected by the queue lock, RCU is used to access it
+ *      from the readers.
+ *    o All the other fields are protected by the @bfqd queue lock.
+ */
+struct bfq_group {
+	struct bfq_entity entity;
+	struct bfq_sched_data sched_data;
+
+	struct hlist_node group_node;
+	struct hlist_node bfqd_node;
+
+	void *bfqd;
+
+	struct bfq_queue *async_bfqq[2][IOPRIO_BE_NR];
+	struct bfq_queue *async_idle_bfqq;
+
+	struct bfq_entity *my_entity;
+};
+
+/**
+ * struct bfqio_cgroup - bfq cgroup data structure.
+ * @css: subsystem state for bfq in the containing cgroup.
+ * @ioprio: cgroup ioprio.
+ * @ioprio_class: cgroup ioprio_class.
+ * @lock: spinlock that protects @ioprio, @ioprio_class and @group_data.
+ * @group_data: list containing the bfq_group belonging to this cgroup.
+ *
+ * @group_data is accessed using RCU, with @lock protecting the updates,
+ * @ioprio and @ioprio_class are protected by @lock.
+ */
+struct bfqio_cgroup {
+	struct cgroup_subsys_state css;
+
+	unsigned short ioprio, ioprio_class;
+
+	spinlock_t lock;
+	struct hlist_head group_data;
+};
+#else
+struct bfq_group {
+	struct bfq_sched_data sched_data;
+
+	struct bfq_queue *async_bfqq[2][IOPRIO_BE_NR];
+	struct bfq_queue *async_idle_bfqq;
+};
+#endif
+
+static inline struct bfq_service_tree *
+bfq_entity_service_tree(struct bfq_entity *entity)
+{
+	struct bfq_sched_data *sched_data = entity->sched_data;
+	unsigned int idx = entity->ioprio_class - 1;
+
+	BUG_ON(idx >= BFQ_IOPRIO_CLASSES);
+	BUG_ON(sched_data == NULL);
+
+	return sched_data->service_tree + idx;
+}
+
+static inline struct bfq_queue *cic_to_bfqq(struct cfq_io_context *cic,
+					    int is_sync)
+{
+	return cic->cfqq[!!is_sync];
+}
+
+static inline void cic_set_bfqq(struct cfq_io_context *cic,
+				struct bfq_queue *bfqq, int is_sync)
+{
+	cic->cfqq[!!is_sync] = bfqq;
+}
+
+static inline void call_for_each_cic(struct io_context *ioc,
+				     void (*func)(struct io_context *,
+				     struct cfq_io_context *))
+{
+	struct cfq_io_context *cic;
+	struct hlist_node *n;
+
+	rcu_read_lock();
+	hlist_for_each_entry_rcu(cic, n, &ioc->bfq_cic_list, cic_list)
+		func(ioc, cic);
+	rcu_read_unlock();
+}
+
+/**
+ * bfq_get_bfqd_locked - get a lock to a bfqd using a RCU protected pointer.
+ * @ptr: a pointer to a bfqd.
+ * @flags: storage for the flags to be saved.
+ *
+ * This function allows cic->key and bfqg->bfqd to be protected by the
+ * queue lock of the bfqd they reference; the pointer is dereferenced
+ * under RCU, so the storage for bfqd is assured to be safe as long
+ * as the RCU read side critical section does not end.  After the
+ * bfqd->queue->queue_lock is taken the pointer is rechecked, to be
+ * sure that no other writer accessed it.  If we raced with a writer,
+ * the function returns NULL, with the queue unlocked, otherwise it
+ * returns the dereferenced pointer, with the queue locked.
+ */
+static inline struct bfq_data *bfq_get_bfqd_locked(void **ptr,
+						   unsigned long *flags)
+{
+	struct bfq_data *bfqd;
+
+	rcu_read_lock();
+	bfqd = rcu_dereference(*(struct bfq_data **)ptr);
+	if (bfqd != NULL) {
+		spin_lock_irqsave(bfqd->queue->queue_lock, *flags);
+		if (*ptr == bfqd)
+			goto out;
+		spin_unlock_irqrestore(bfqd->queue->queue_lock, *flags);
+		bfqd = NULL;
+	}
+
+out:
+	rcu_read_unlock();
+	return bfqd;
+}
+
+static inline void bfq_put_bfqd_unlock(struct bfq_data *bfqd,
+				       unsigned long *flags)
+{
+	spin_unlock_irqrestore(bfqd->queue->queue_lock, *flags);
+}
+
+static void bfq_changed_ioprio(struct io_context *ioc,
+			       struct cfq_io_context *cic);
+static void bfq_put_queue(struct bfq_queue *bfqq);
+static void bfq_dispatch_insert(struct request_queue *q, struct request *rq);
+static struct bfq_queue *bfq_get_queue(struct bfq_data *bfqd,
+				       struct bfq_group *bfqg, int is_sync,
+				       struct io_context *ioc, gfp_t gfp_mask);
+static void bfq_put_async_queues(struct bfq_data *bfqd, struct bfq_group *bfqg);
+static void bfq_exit_bfqq(struct bfq_data *bfqd, struct bfq_queue *bfqq);
+#endif
diff -Nru linux-source-2.6.28/block/bfq-ioc.c linux-source-2.6.28-gs-bfq/block/bfq-ioc.c
--- linux-source-2.6.28/block/bfq-ioc.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-source-2.6.28-gs-bfq/block/bfq-ioc.c	2009-04-28 12:01:06.000000000 +0200
@@ -0,0 +1,375 @@
+/*
+ * BFQ: I/O context handling.
+ *
+ * Based on ideas and code from CFQ:
+ * Copyright (C) 2003 Jens Axboe <axboe@kernel.dk>
+ *
+ * Copyright (C) 2008 Fabio Checconi <fabio@gandalf.sssup.it>
+ *		      Paolo Valente <paolo.valente@unimore.it>
+ */
+
+/**
+ * bfq_cic_free_rcu - deferred cic freeing.
+ * @head: RCU head of the cic to free.
+ *
+ * Free the cic containing @head and, if it was the last one and
+ * the module is exiting wake up anyone waiting for its deallocation
+ * (see bfq_exit()).
+ */
+static void bfq_cic_free_rcu(struct rcu_head *head)
+{
+	struct cfq_io_context *cic;
+
+	cic = container_of(head, struct cfq_io_context, rcu_head);
+
+	kmem_cache_free(bfq_ioc_pool, cic);
+	elv_ioc_count_dec(bfq_ioc_count);
+
+	if (bfq_ioc_gone != NULL) {
+		spin_lock(&bfq_ioc_gone_lock);
+		if (bfq_ioc_gone != NULL &&
+		    !elv_ioc_count_read(bfq_ioc_count)) {
+			complete(bfq_ioc_gone);
+			bfq_ioc_gone = NULL;
+		}
+		spin_unlock(&bfq_ioc_gone_lock);
+	}
+}
+
+static void bfq_cic_free(struct cfq_io_context *cic)
+{
+	call_rcu(&cic->rcu_head, bfq_cic_free_rcu);
+}
+
+/**
+ * cic_free_func - disconnect a cic ready to be freed.
+ * @ioc: the io_context @cic belongs to.
+ * @cic: the cic to be freed.
+ *
+ * Remove @cic from the @ioc radix tree hash and from its cic list,
+ * deferring the deallocation of @cic to the end of the current RCU
+ * grace period.  This assumes that __bfq_exit_single_io_context()
+ * has already been called for @cic.
+ */
+static void cic_free_func(struct io_context *ioc, struct cfq_io_context *cic)
+{
+	unsigned long flags;
+
+	BUG_ON(cic->dead_key == 0);
+
+	spin_lock_irqsave(&ioc->lock, flags);
+	radix_tree_delete(&ioc->bfq_radix_root, cic->dead_key);
+	hlist_del_init_rcu(&cic->cic_list);
+	spin_unlock_irqrestore(&ioc->lock, flags);
+
+	bfq_cic_free(cic);
+}
+
+static void bfq_free_io_context(struct io_context *ioc)
+{
+	/*
+	 * ioc->refcount is zero here, or we are called from elv_unregister(),
+	 * so no more cic's are allowed to be linked into this ioc.  So it
+	 * should be ok to iterate over the known list, we will see all cic's
+	 * since no new ones are added.
+	 */
+	call_for_each_cic(ioc, cic_free_func);
+}
+
+/**
+ * __bfq_exit_single_io_context - deassociate @cic from any running task.
+ * @bfqd: bfq_data on which @cic is valid.
+ * @cic: the cic being exited.
+ *
+ * Whenever no more tasks are using @cic or @bfqd is deallocated we
+ * need to invalidate its entry in the radix tree hash table and to
+ * release the queues it refers to.  Save the key used for insertion
+ * in @cic->dead_key to remove @cic from the radix tree later and assign
+ * %NULL to its search key to prevent future lookups to succeed on it.
+ *
+ * Called under the queue lock.
+ */
+static void __bfq_exit_single_io_context(struct bfq_data *bfqd,
+					 struct cfq_io_context *cic)
+{
+	struct io_context *ioc = cic->ioc;
+
+	list_del_init(&cic->queue_list);
+
+	/*
+	 * Make sure key == NULL is seen for dead queues.
+	 */
+	cic->dead_key = (unsigned long)cic->key;
+	smp_wmb();
+
+	rcu_assign_pointer(cic->key, NULL);
+
+	/*
+	 * No write-side locking as no task is using @ioc (they're exited
+	 * or bfqd is being deallocated.
+	 */
+	if (ioc->ioc_data == cic)
+		rcu_assign_pointer(ioc->ioc_data, NULL);
+
+	if (cic->cfqq[ASYNC] != NULL) {
+		bfq_exit_bfqq(bfqd, cic->cfqq[ASYNC]);
+		cic->cfqq[ASYNC] = NULL;
+	}
+
+	if (cic->cfqq[SYNC] != NULL) {
+		bfq_exit_bfqq(bfqd, cic->cfqq[SYNC]);
+		cic->cfqq[SYNC] = NULL;
+	}
+}
+
+/**
+ * bfq_exit_single_io_context - deassociate @cic from @ioc (unlocked version).
+ * @ioc: the io_context @cic belongs to.
+ * @cic: the cic being exited.
+ *
+ * Take the queue lock and call __bfq_exit_single_io_context() to do the
+ * rest of the work.  We take care of possible races with bfq_exit_queue()
+ * using bfq_get_bfqd_locked() (and abusing a little bit the RCU mechanism).
+ */
+static void bfq_exit_single_io_context(struct io_context *ioc,
+				       struct cfq_io_context *cic)
+{
+	struct bfq_data *bfqd;
+	unsigned long uninitialized_var(flags);
+
+	bfqd = bfq_get_bfqd_locked(&cic->key, &flags);
+	if (bfqd != NULL) {
+		__bfq_exit_single_io_context(bfqd, cic);
+		bfq_put_bfqd_unlock(bfqd, &flags);
+	}
+}
+
+/**
+ * bfq_exit_io_context - deassociate @ioc from all cics it owns.
+ * @ioc: the @ioc being exited.
+ *
+ * No more processes are using @ioc we need to clean up and put the
+ * internal structures we have that belongs to that process.  Loop
+ * through all its cics, locking their queues and exiting them.
+ */
+static void bfq_exit_io_context(struct io_context *ioc)
+{
+	call_for_each_cic(ioc, bfq_exit_single_io_context);
+}
+
+static struct cfq_io_context *bfq_alloc_io_context(struct bfq_data *bfqd,
+						   gfp_t gfp_mask)
+{
+	struct cfq_io_context *cic;
+
+	cic = kmem_cache_alloc_node(bfq_ioc_pool, gfp_mask | __GFP_ZERO,
+							bfqd->queue->node);
+	if (cic != NULL) {
+		cic->last_end_request = jiffies;
+		INIT_LIST_HEAD(&cic->queue_list);
+		INIT_HLIST_NODE(&cic->cic_list);
+		cic->dtor = bfq_free_io_context;
+		cic->exit = bfq_exit_io_context;
+		elv_ioc_count_inc(bfq_ioc_count);
+	}
+
+	return cic;
+}
+
+/**
+ * bfq_drop_dead_cic - free an exited cic.
+ * @bfqd: bfq data for the device in use.
+ * @ioc: io_context owning @cic.
+ * @cic: the @cic to free.
+ *
+ * We drop cfq io contexts lazily, so we may find a dead one.
+ */
+static void bfq_drop_dead_cic(struct bfq_data *bfqd, struct io_context *ioc,
+			      struct cfq_io_context *cic)
+{
+	unsigned long flags;
+
+	WARN_ON(!list_empty(&cic->queue_list));
+
+	spin_lock_irqsave(&ioc->lock, flags);
+
+	BUG_ON(ioc->ioc_data == cic);
+
+	/*
+	 * With shared I/O contexts two lookups may race and drop the
+	 * same cic more than one time: RCU guarantees that the storage
+	 * will not be freed too early, here we make sure that we do
+	 * not try to remove the cic from the hashing structures multiple
+	 * times.
+	 */
+	if (!hlist_unhashed(&cic->cic_list)) {
+		radix_tree_delete(&ioc->bfq_radix_root, (unsigned long)bfqd);
+		hlist_del_init_rcu(&cic->cic_list);
+		bfq_cic_free(cic);
+	}
+
+	spin_unlock_irqrestore(&ioc->lock, flags);
+}
+
+/**
+ * bfq_cic_lookup - search into @ioc a cic associated to @bfqd.
+ * @bfqd: the lookup key.
+ * @ioc: the io_context of the process doing I/O.
+ *
+ * If @ioc already has a cic associated to @bfqd return it, return %NULL
+ * otherwise.
+ */
+static struct cfq_io_context *bfq_cic_lookup(struct bfq_data *bfqd,
+					     struct io_context *ioc)
+{
+	struct cfq_io_context *cic;
+	unsigned long flags;
+	void *k;
+
+	if (unlikely(ioc == NULL))
+		return NULL;
+
+	rcu_read_lock();
+
+	/* We maintain a last-hit cache, to avoid browsing over the tree. */
+	cic = rcu_dereference(ioc->ioc_data);
+	if (cic != NULL) {
+		k = rcu_dereference(cic->key);
+		if (k == bfqd)
+			goto out;
+	}
+
+	do {
+		cic = radix_tree_lookup(&ioc->bfq_radix_root,
+					(unsigned long)bfqd);
+		if (cic == NULL)
+			goto out;
+
+		k = rcu_dereference(cic->key);
+		if (unlikely(k == NULL)) {
+			rcu_read_unlock();
+			bfq_drop_dead_cic(bfqd, ioc, cic);
+			rcu_read_lock();
+			continue;
+		}
+
+		spin_lock_irqsave(&ioc->lock, flags);
+		rcu_assign_pointer(ioc->ioc_data, cic);
+		spin_unlock_irqrestore(&ioc->lock, flags);
+		break;
+	} while (1);
+
+out:
+	rcu_read_unlock();
+
+	return cic;
+}
+
+/**
+ * bfq_cic_link - add @cic to @ioc.
+ * @bfqd: bfq_data @cic refers to.
+ * @ioc: io_context @cic belongs to.
+ * @cic: the cic to link.
+ * @gfp_mask: the mask to use for radix tree preallocations.
+ *
+ * Add @cic to @ioc, using @bfqd as the search key.  This enables us to
+ * lookup the process specific cfq io context when entered from the block
+ * layer.  Also adds @cic to a per-bfqd list, used when this queue is
+ * removed.
+ */
+static int bfq_cic_link(struct bfq_data *bfqd, struct io_context *ioc,
+			struct cfq_io_context *cic, gfp_t gfp_mask)
+{
+	unsigned long flags;
+	int ret;
+
+	ret = radix_tree_preload(gfp_mask);
+	if (ret == 0) {
+		cic->ioc = ioc;
+
+		/* No write-side locking, cic is not published yet. */
+		rcu_assign_pointer(cic->key, bfqd);
+
+		spin_lock_irqsave(&ioc->lock, flags);
+		ret = radix_tree_insert(&ioc->bfq_radix_root,
+					(unsigned long)bfqd, cic);
+		if (ret == 0)
+			hlist_add_head_rcu(&cic->cic_list, &ioc->bfq_cic_list);
+		spin_unlock_irqrestore(&ioc->lock, flags);
+
+		radix_tree_preload_end();
+
+		if (ret == 0) {
+			spin_lock_irqsave(bfqd->queue->queue_lock, flags);
+			list_add(&cic->queue_list, &bfqd->cic_list);
+			spin_unlock_irqrestore(bfqd->queue->queue_lock, flags);
+		}
+	}
+
+	if (ret != 0)
+		printk(KERN_ERR "bfq: cic link failed!\n");
+
+	return ret;
+}
+
+/**
+ * bfq_ioc_set_ioprio - signal a priority change to the cics belonging to @ioc.
+ * @ioc: the io_context changing its priority.
+ */
+static inline void bfq_ioc_set_ioprio(struct io_context *ioc)
+{
+	call_for_each_cic(ioc, bfq_changed_ioprio);
+}
+
+/**
+ * bfq_get_io_context - return the @cic associated to @bfqd in @ioc.
+ * @bfqd: the search key.
+ * @gfp_mask: the mask to use for cic allocation.
+ *
+ * Setup general io context and cfq io context.  There can be several cfq
+ * io contexts per general io context, if this process is doing io to more
+ * than one device managed by cfq.
+ */
+static struct cfq_io_context *bfq_get_io_context(struct bfq_data *bfqd,
+						 gfp_t gfp_mask)
+{
+	struct io_context *ioc = NULL;
+	struct cfq_io_context *cic;
+
+	might_sleep_if(gfp_mask & __GFP_WAIT);
+
+	ioc = get_io_context(gfp_mask, bfqd->queue->node);
+	if (ioc == NULL)
+		return NULL;
+
+	/* Lookup for an existing cic. */
+	cic = bfq_cic_lookup(bfqd, ioc);
+	if (cic != NULL)
+		goto out;
+
+	/* Alloc one if needed. */
+	cic = bfq_alloc_io_context(bfqd, gfp_mask);
+	if (cic == NULL)
+		goto err;
+
+	/* Link it into the ioc's radix tree and cic list. */
+	if (bfq_cic_link(bfqd, ioc, cic, gfp_mask) != 0)
+		goto err_free;
+
+out:
+	/*
+	 * test_and_clear_bit() implies a memory barrier, paired with
+	 * the wmb() in fs/ioprio.c, so the value seen for ioprio is the
+	 * new one.
+	 */
+	if (unlikely(test_and_clear_bit(IOC_BFQ_IOPRIO_CHANGED,
+					ioc->ioprio_changed)))
+		bfq_ioc_set_ioprio(ioc);
+
+	return cic;
+err_free:
+	bfq_cic_free(cic);
+err:
+	put_io_context(ioc);
+	return NULL;
+}
diff -Nru linux-source-2.6.28/block/bfq-iosched.c linux-source-2.6.28-gs-bfq/block/bfq-iosched.c
--- linux-source-2.6.28/block/bfq-iosched.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-source-2.6.28-gs-bfq/block/bfq-iosched.c	2009-04-28 12:01:06.000000000 +0200
@@ -0,0 +1,2010 @@
+/*
+ * BFQ, or Budget Fair Queueing, disk scheduler.
+ *
+ * Based on ideas and code from CFQ:
+ * Copyright (C) 2003 Jens Axboe <axboe@kernel.dk>
+ *
+ * Copyright (C) 2008 Fabio Checconi <fabio@gandalf.sssup.it>
+ *		      Paolo Valente <paolo.valente@unimore.it>
+ *
+ * BFQ is a proportional share disk scheduling algorithm based on CFQ,
+ * that uses the B-WF2Q+ internal scheduler to assign budgets (i.e.,
+ * slices in the service domain) to the tasks accessing the disk.  It
+ * has been introduced in [1], where the interested reader can find an
+ * accurate description of the algorithm, the guarantees it provides
+ * and their formal proofs.  With respect to the algorithm presented
+ * in the paper, this implementation adds a timeout to limit the maximum
+ * time a queue can spend to complete its assigned budget, and a
+ * hierarchical extension, based on H-WF2Q+.
+ *
+ * B-WF2Q+ is based on WF2Q+, that is described in [2], together with
+ * H-WF2Q+, while the augmented tree used to implement B-WF2Q+ with O(log N)
+ * complexity derives from the one introduced with EEVDF in [3].
+ *
+ * [1] P. Valente and F. Checconi, ``High Throughput Disk Scheduling
+ *     with Deterministic Guarantees on Bandwidth Distribution,'' to be
+ *     published.
+ *
+ *     http://algo.ing.unimo.it/people/paolo/disk_sched/bfq.pdf
+ *
+ * [2] Jon C.R. Bennett and H. Zhang, ``Hierarchical Packet Fair Queueing
+ *     Algorithms,'' IEEE/ACM Transactions on Networking, 5(5):675-689,
+ *     Oct 1997.
+ *
+ *     http://www.cs.cmu.edu/~hzhang/papers/TON-97-Oct.ps.gz
+ *
+ * [3] I. Stoica and H. Abdel-Wahab, ``Earliest Eligible Virtual Deadline
+ *     First: A Flexible and Accurate Mechanism for Proportional Share
+ *     Resource Allocation,'' technical report.
+ *
+ *     http://www.cs.berkeley.edu/~istoica/papers/eevdf-tr-95.pdf
+ */
+#include <linux/module.h>
+#include <linux/blkdev.h>
+#include <linux/cgroup.h>
+#include <linux/elevator.h>
+#include <linux/rbtree.h>
+#include <linux/ioprio.h>
+#include "bfq.h"
+
+/* Max nr of dispatches in one round of service. */
+static const int bfq_quantum = 4;
+
+/* Expiration time of each request (jiffies). */
+static const int bfq_fifo_expire[2] = { HZ / 4, HZ / 8 };
+
+/* Maximum backwards seek, in KiB. */
+static const int bfq_back_max = 16 * 1024;
+
+/* Penalty of a backwards seek. */
+static const int bfq_back_penalty = 2;
+
+/* Idling period duration (jiffies). */
+static int bfq_slice_idle = HZ / 125;
+
+/* Default maximum budget values (sectors). */
+static const int bfq_max_budget = 16 * 1024;
+static const int bfq_max_budget_async_rq = 4;
+
+/* Default timeout values (jiffies), approximating CFQ defaults. */
+static const int bfq_timeout_sync = HZ / 8;
+static int bfq_timeout_async = HZ / 25;
+
+struct kmem_cache *bfq_pool;
+struct kmem_cache *bfq_ioc_pool;
+
+static DEFINE_PER_CPU(unsigned long, bfq_ioc_count);
+static struct completion *bfq_ioc_gone;
+static DEFINE_SPINLOCK(bfq_ioc_gone_lock);
+
+/* Below this threshold (in ms), we consider thinktime immediate. */
+#define BFQ_MIN_TT		2
+
+/* hw_tag detection: parallel requests threshold and min samples needed. */
+#define BFQ_HW_QUEUE_THRESHOLD	4
+#define BFQ_HW_QUEUE_SAMPLES	32
+
+/* Budget feedback step. */
+#define BFQ_BUDGET_STEP		128
+
+/* Min samples used for peak rate estimation (for autotuning). */
+#define BFQ_PEAK_RATE_SAMPLES	32
+
+/* Shift used for peak rate fixed precision calculations. */
+#define BFQ_RATE_SHIFT		16
+
+#define BFQ_SERVICE_TREE_INIT	((struct bfq_service_tree)		\
+				{ RB_ROOT, RB_ROOT, NULL, NULL, 0, 0 })
+
+#define RQ_CIC(rq)		\
+	((struct cfq_io_context *) (rq)->elevator_private)
+#define RQ_BFQQ(rq)		((rq)->elevator_private2)
+
+#include "bfq-ioc.c"
+#include "bfq-sched.c"
+#include "bfq-cgroup.c"
+
+static inline int bfq_class_idle(struct bfq_queue *bfqq)
+{
+	return bfqq->entity.ioprio_class == IOPRIO_CLASS_IDLE;
+}
+
+static inline int bfq_sample_valid(int samples)
+{
+	return samples > 80;
+}
+
+/*
+ * We regard a request as SYNC, if either it's a read or has the SYNC bit
+ * set (in which case it could also be a direct WRITE).
+ */
+static inline int bfq_bio_sync(struct bio *bio)
+{
+	if (bio_data_dir(bio) == READ || bio_sync(bio))
+		return 1;
+
+	return 0;
+}
+
+/*
+ * Scheduler run of queue, if there are requests pending and no one in the
+ * driver that will restart queueing.
+ */
+static inline void bfq_schedule_dispatch(struct bfq_data *bfqd)
+{
+	if (bfqd->queued != 0) {
+		bfq_log(bfqd, "schedule dispatch");
+		kblockd_schedule_work(bfqd->queue, &bfqd->unplug_work);
+	}
+}
+
+static inline int bfq_queue_empty(struct request_queue *q)
+{
+	struct bfq_data *bfqd = q->elevator->elevator_data;
+
+	return bfqd->queued == 0;
+}
+
+/*
+ * Lifted from AS - choose which of rq1 and rq2 that is best served now.
+ * We choose the request that is closesr to the head right now.  Distance
+ * behind the head is penalized and only allowed to a certain extent.
+ */
+static struct request *bfq_choose_req(struct bfq_data *bfqd,
+				      struct request *rq1,
+				      struct request *rq2)
+{
+	sector_t last, s1, s2, d1 = 0, d2 = 0;
+	unsigned long back_max;
+#define BFQ_RQ1_WRAP	0x01 /* request 1 wraps */
+#define BFQ_RQ2_WRAP	0x02 /* request 2 wraps */
+	unsigned wrap = 0; /* bit mask: requests behind the disk head? */
+
+	if (rq1 == NULL || rq1 == rq2)
+		return rq2;
+	if (rq2 == NULL)
+		return rq1;
+
+	if (rq_is_sync(rq1) && !rq_is_sync(rq2))
+		return rq1;
+	else if (rq_is_sync(rq2) && !rq_is_sync(rq1))
+		return rq2;
+	if (rq_is_meta(rq1) && !rq_is_meta(rq2))
+		return rq1;
+	else if (rq_is_meta(rq2) && !rq_is_meta(rq1))
+		return rq2;
+
+	s1 = rq1->sector;
+	s2 = rq2->sector;
+
+	last = bfqd->last_position;
+
+	/*
+	 * by definition, 1KiB is 2 sectors
+	 */
+	back_max = bfqd->bfq_back_max * 2;
+
+	/*
+	 * Strict one way elevator _except_ in the case where we allow
+	 * short backward seeks which are biased as twice the cost of a
+	 * similar forward seek.
+	 */
+	if (s1 >= last)
+		d1 = s1 - last;
+	else if (s1 + back_max >= last)
+		d1 = (last - s1) * bfqd->bfq_back_penalty;
+	else
+		wrap |= BFQ_RQ1_WRAP;
+
+	if (s2 >= last)
+		d2 = s2 - last;
+	else if (s2 + back_max >= last)
+		d2 = (last - s2) * bfqd->bfq_back_penalty;
+	else
+		wrap |= BFQ_RQ2_WRAP;
+
+	/* Found required data */
+
+	/*
+	 * By doing switch() on the bit mask "wrap" we avoid having to
+	 * check two variables for all permutations: --> faster!
+	 */
+	switch (wrap) {
+	case 0: /* common case for CFQ: rq1 and rq2 not wrapped */
+		if (d1 < d2)
+			return rq1;
+		else if (d2 < d1)
+			return rq2;
+		else {
+			if (s1 >= s2)
+				return rq1;
+			else
+				return rq2;
+		}
+
+	case BFQ_RQ2_WRAP:
+		return rq1;
+	case BFQ_RQ1_WRAP:
+		return rq2;
+	case (BFQ_RQ1_WRAP|BFQ_RQ2_WRAP): /* both rqs wrapped */
+	default:
+		/*
+		 * Since both rqs are wrapped,
+		 * start with the one that's further behind head
+		 * (--> only *one* back seek required),
+		 * since back seek takes more time than forward.
+		 */
+		if (s1 <= s2)
+			return rq1;
+		else
+			return rq2;
+	}
+}
+
+static struct request *bfq_find_next_rq(struct bfq_data *bfqd,
+					struct bfq_queue *bfqq,
+					struct request *last)
+{
+	struct rb_node *rbnext = rb_next(&last->rb_node);
+	struct rb_node *rbprev = rb_prev(&last->rb_node);
+	struct request *next = NULL, *prev = NULL;
+
+	BUG_ON(RB_EMPTY_NODE(&last->rb_node));
+
+	if (rbprev != NULL)
+		prev = rb_entry_rq(rbprev);
+
+	if (rbnext != NULL)
+		next = rb_entry_rq(rbnext);
+	else {
+		rbnext = rb_first(&bfqq->sort_list);
+		if (rbnext && rbnext != &last->rb_node)
+			next = rb_entry_rq(rbnext);
+	}
+
+	return bfq_choose_req(bfqd, next, prev);
+}
+
+static void bfq_del_rq_rb(struct request *rq)
+{
+	struct bfq_queue *bfqq = RQ_BFQQ(rq);
+	struct bfq_data *bfqd = bfqq->bfqd;
+	const int sync = rq_is_sync(rq);
+
+	BUG_ON(bfqq->queued[sync] == 0);
+	bfqq->queued[sync]--;
+	bfqd->queued--;
+
+	elv_rb_del(&bfqq->sort_list, rq);
+
+	if (bfq_bfqq_busy(bfqq) && bfqq != bfqd->active_queue &&
+	    RB_EMPTY_ROOT(&bfqq->sort_list))
+		bfq_del_bfqq_busy(bfqd, bfqq, 1);
+}
+
+/**
+ * bfq_updated_next_req - update the queue after a new next_rq selection.
+ * @bfqd: the device data the queue belongs to.
+ * @bfqq: the queue to update.
+ *
+ * Whenever the first request of a queue changes we try to allocate it
+ * enough service (if it has grown), or to anticipate its finish time
+ * (if it has shrinked), to reduce the time it has to wait, still taking
+ * into account the queue budget.  We try to avoid the queue having not
+ * enough service allocated for its first request, thus having to go
+ * through two dispatch rounds to actually dispatch the request.
+ */
+static void bfq_updated_next_req(struct bfq_data *bfqd,
+				 struct bfq_queue *bfqq)
+{
+	struct bfq_entity *entity = &bfqq->entity;
+	struct bfq_service_tree *st = bfq_entity_service_tree(entity);
+	struct request *next_rq = bfqq->next_rq;
+	bfq_service_t new_budget;
+
+	if (next_rq == NULL)
+		return;
+
+	if (bfqq == bfqd->active_queue)
+		/*
+		 * In order not to break guarantees, budgets cannot be
+		 * changed after an entity has been selected.
+		 */
+		return;
+
+	BUG_ON(entity->tree != &st->active);
+	BUG_ON(entity == entity->sched_data->active_entity);
+
+	new_budget = max(bfqq->max_budget, next_rq->hard_nr_sectors);
+	entity->budget = new_budget;
+	bfq_log_bfqq(bfqd, bfqq, "budget=%lu", new_budget);
+	bfq_activate_bfqq(bfqd, bfqq);
+}
+
+static void bfq_add_rq_rb(struct request *rq)
+{
+	struct bfq_queue *bfqq = RQ_BFQQ(rq);
+	struct bfq_entity *entity = &bfqq->entity;
+	struct bfq_data *bfqd = bfqq->bfqd;
+	struct request *__alias, *next_rq;
+
+	bfqq->queued[rq_is_sync(rq)]++;
+	bfqd->queued++;
+
+	/*
+	 * Looks a little odd, but the first insert might return an alias,
+	 * if that happens, put the alias on the dispatch list.
+	 */
+	while ((__alias = elv_rb_add(&bfqq->sort_list, rq)) != NULL)
+		bfq_dispatch_insert(bfqd->queue, __alias);
+
+	/*
+	 * check if this request is a better next-serve candidate
+	 */
+	next_rq = bfq_choose_req(bfqd, bfqq->next_rq, rq);
+	BUG_ON(next_rq == NULL);
+	bfqq->next_rq = next_rq;
+
+	if (!bfq_bfqq_busy(bfqq)) {
+		entity->budget = max(bfqq->max_budget,
+				     next_rq->hard_nr_sectors);
+		bfq_add_bfqq_busy(bfqd, bfqq);
+	} else
+		bfq_updated_next_req(bfqd, bfqq);
+}
+
+static void bfq_reposition_rq_rb(struct bfq_queue *bfqq, struct request *rq)
+{
+	elv_rb_del(&bfqq->sort_list, rq);
+	bfqq->queued[rq_is_sync(rq)]--;
+	bfqq->bfqd->queued--;
+	bfq_add_rq_rb(rq);
+}
+
+static struct request *bfq_find_rq_fmerge(struct bfq_data *bfqd,
+					  struct bio *bio)
+{
+	struct task_struct *tsk = current;
+	struct cfq_io_context *cic;
+	struct bfq_queue *bfqq;
+
+	cic = bfq_cic_lookup(bfqd, tsk->io_context);
+	if (cic == NULL)
+		return NULL;
+
+	bfqq = cic_to_bfqq(cic, bfq_bio_sync(bio));
+	if (bfqq != NULL) {
+		sector_t sector = bio->bi_sector + bio_sectors(bio);
+
+		return elv_rb_find(&bfqq->sort_list, sector);
+	}
+
+	return NULL;
+}
+
+static void bfq_activate_request(struct request_queue *q, struct request *rq)
+{
+	struct bfq_data *bfqd = q->elevator->elevator_data;
+
+	bfqd->rq_in_driver++;
+	bfqd->last_position = rq->hard_sector + rq->hard_nr_sectors;
+}
+
+static void bfq_deactivate_request(struct request_queue *q, struct request *rq)
+{
+	struct bfq_data *bfqd = q->elevator->elevator_data;
+
+	WARN_ON(bfqd->rq_in_driver == 0);
+	bfqd->rq_in_driver--;
+}
+
+static void bfq_remove_request(struct request *rq)
+{
+	struct bfq_queue *bfqq = RQ_BFQQ(rq);
+	struct bfq_data *bfqd = bfqq->bfqd;
+
+	if (bfqq->next_rq == rq) {
+		bfqq->next_rq = bfq_find_next_rq(bfqd, bfqq, rq);
+		bfq_updated_next_req(bfqd, bfqq);
+	}
+
+	list_del_init(&rq->queuelist);
+	bfq_del_rq_rb(rq);
+
+	if (rq_is_meta(rq)) {
+		WARN_ON(bfqq->meta_pending == 0);
+		bfqq->meta_pending--;
+	}
+}
+
+static int bfq_merge(struct request_queue *q, struct request **req,
+		     struct bio *bio)
+{
+	struct bfq_data *bfqd = q->elevator->elevator_data;
+	struct request *__rq;
+
+	__rq = bfq_find_rq_fmerge(bfqd, bio);
+	if (__rq != NULL && elv_rq_merge_ok(__rq, bio)) {
+		*req = __rq;
+		return ELEVATOR_FRONT_MERGE;
+	}
+
+	return ELEVATOR_NO_MERGE;
+}
+
+static void bfq_merged_request(struct request_queue *q, struct request *req,
+			       int type)
+{
+	if (type == ELEVATOR_FRONT_MERGE) {
+		struct bfq_queue *bfqq = RQ_BFQQ(req);
+
+		bfq_reposition_rq_rb(bfqq, req);
+	}
+}
+
+static void bfq_merged_requests(struct request_queue *q, struct request *rq,
+				struct request *next)
+{
+	/*
+	 * reposition in fifo if next is older than rq
+	 */
+	if (!list_empty(&rq->queuelist) && !list_empty(&next->queuelist) &&
+	    time_before(next->start_time, rq->start_time))
+		list_move(&rq->queuelist, &next->queuelist);
+
+	bfq_remove_request(next);
+}
+
+static int bfq_allow_merge(struct request_queue *q, struct request *rq,
+			   struct bio *bio)
+{
+	struct bfq_data *bfqd = q->elevator->elevator_data;
+	struct cfq_io_context *cic;
+	struct bfq_queue *bfqq;
+
+	/* Disallow merge of a sync bio into an async request. */
+	if (bfq_bio_sync(bio) && !rq_is_sync(rq))
+		return 0;
+
+	/*
+	 * Lookup the bfqq that this bio will be queued with. Allow
+	 * merge only if rq is queued there.
+	 */
+	cic = bfq_cic_lookup(bfqd, current->io_context);
+	if (cic == NULL)
+		return 0;
+
+	bfqq = cic_to_bfqq(cic, bfq_bio_sync(bio));
+	if (bfqq == RQ_BFQQ(rq))
+		return 1;
+
+	return 0;
+}
+
+static void __bfq_set_active_queue(struct bfq_data *bfqd,
+				   struct bfq_queue *bfqq)
+{
+	if (bfqq != NULL) {
+		bfq_mark_bfqq_must_alloc(bfqq);
+		bfq_mark_bfqq_budget_new(bfqq);
+		bfq_clear_bfqq_fifo_expire(bfqq);
+
+		bfqq->budgets_assigned = (bfqq->budgets_assigned*7 + 256) / 8;
+
+		bfq_log_bfqq(bfqd, bfqq, "active");
+	}
+
+	bfqd->active_queue = bfqq;
+}
+
+/*
+ * Get and set a new active queue for service.
+ */
+static struct bfq_queue *bfq_set_active_queue(struct bfq_data *bfqd)
+{
+	struct bfq_queue *bfqq;
+
+	bfqq = bfq_get_next_queue(bfqd);
+	__bfq_set_active_queue(bfqd, bfqq);
+	return bfqq;
+}
+
+#define CIC_SEEKY(cic) ((cic)->seek_mean > (8 * 1024))
+
+static void bfq_arm_slice_timer(struct bfq_data *bfqd)
+{
+	struct bfq_queue *bfqq = bfqd->active_queue;
+	struct cfq_io_context *cic;
+	unsigned long sl;
+
+	WARN_ON(!RB_EMPTY_ROOT(&bfqq->sort_list));
+
+	/* Idling is disabled, either manually or by past process history. */
+	if (bfqd->bfq_slice_idle == 0 || !bfq_bfqq_idle_window(bfqq))
+		return;
+
+	/* Tasks have exited, don't wait. */
+	cic = bfqd->active_cic;
+	if (cic == NULL || atomic_read(&cic->ioc->nr_tasks) == 0)
+		return;
+
+	bfq_mark_bfqq_wait_request(bfqq);
+
+	/*
+	 * we don't want to idle for seeks, but we do want to allow
+	 * fair distribution of slice time for a process doing back-to-back
+	 * seeks. so allow a little bit of time for him to submit a new rq
+	 */
+	sl = bfqd->bfq_slice_idle;
+	if (bfq_sample_valid(cic->seek_samples) && CIC_SEEKY(cic))
+		sl = min(sl, msecs_to_jiffies(BFQ_MIN_TT));
+
+	bfqd->last_idling_start = ktime_get();
+	mod_timer(&bfqd->idle_slice_timer, jiffies + sl);
+	bfq_log(bfqd, "arm idle: %lu", sl);
+}
+
+static void bfq_set_budget_timeout(struct bfq_data *bfqd)
+{
+	struct bfq_queue *bfqq = bfqd->active_queue;
+
+	bfqd->last_budget_start = ktime_get();
+
+	bfq_clear_bfqq_budget_new(bfqq);
+	bfqq->budget_timeout = jiffies +
+		bfqd->bfq_timeout[!!bfq_bfqq_sync(bfqq)];
+}
+
+/*
+ * Move request from internal lists to the request queue dispatch list.
+ */
+static void bfq_dispatch_insert(struct request_queue *q, struct request *rq)
+{
+	struct bfq_data *bfqd = q->elevator->elevator_data;
+	struct bfq_queue *bfqq = RQ_BFQQ(rq);
+
+	bfq_remove_request(rq);
+	bfqq->dispatched++;
+	elv_dispatch_sort(q, rq);
+
+	if (bfq_bfqq_sync(bfqq))
+		bfqd->sync_flight++;
+}
+
+/*
+ * return expired entry, or NULL to just start from scratch in rbtree
+ */
+static struct request *bfq_check_fifo(struct bfq_queue *bfqq)
+{
+	struct bfq_data *bfqd = bfqq->bfqd;
+	struct request *rq;
+	int fifo;
+
+	if (bfq_bfqq_fifo_expire(bfqq))
+		return NULL;
+
+	bfq_mark_bfqq_fifo_expire(bfqq);
+
+	if (list_empty(&bfqq->fifo))
+		return NULL;
+
+	fifo = bfq_bfqq_sync(bfqq);
+	rq = rq_entry_fifo(bfqq->fifo.next);
+
+	if (time_before(jiffies, rq->start_time + bfqd->bfq_fifo_expire[fifo]))
+		return NULL;
+
+	return rq;
+}
+
+static inline bfq_service_t bfq_bfqq_budget_left(struct bfq_queue *bfqq)
+{
+	struct bfq_entity *entity = &bfqq->entity;
+	return entity->budget - entity->service;
+}
+
+static void __bfq_bfqq_expire(struct bfq_data *bfqd, struct bfq_queue *bfqq)
+{
+	BUG_ON(bfqq != bfqd->active_queue);
+
+	__bfq_bfqd_reset_active(bfqd);
+
+	if (RB_EMPTY_ROOT(&bfqq->sort_list))
+		bfq_del_bfqq_busy(bfqd, bfqq, 1);
+	else
+		bfq_activate_bfqq(bfqd, bfqq);
+}
+
+/**
+ * bfq_default_budget - return the default budget for @bfqq on @bfqd.
+ * @bfqd: the device descriptor.
+ * @bfqq: the queue to consider.
+ *
+ * We use 3/4 of the @bfqd maximum budget as the default value
+ * for the max_budget field of the queues.  This lets the feedback
+ * mechanism to start from some middle ground, then the behavior
+ * of the task will drive the heuristics towards high values, if
+ * it behaves as a greedy sequential reader, or towards small values
+ * if it shows a more intermittent behavior.
+ */
+static bfq_service_t bfq_default_budget(struct bfq_data *bfqd,
+					struct bfq_queue *bfqq)
+{
+	bfq_service_t budget;
+
+	/*
+	 * When we need an estimate of the peak rate we need to avoid
+	 * to give budgets that are too short due to previous measurements.
+	 * So, in the first 10 assignments use a ``safe'' budget value.
+	 */
+	if (bfqq->budgets_assigned < 194 && bfqd->bfq_user_max_budget == 0)
+		budget = bfq_max_budget;
+	else
+		budget = bfqd->bfq_max_budget;
+
+	return budget - budget / 4;
+}
+
+static inline bfq_service_t bfq_min_budget(struct bfq_data *bfqd,
+					   struct bfq_queue *bfqq)
+{
+	return bfqd->bfq_max_budget / 2;
+}
+
+/**
+ * __bfq_bfqq_recalc_budget - try to adapt the budget to the @bfqq behavior.
+ * @bfqd: device data.
+ * @bfqq: queue to update.
+ * @reason: reason for expiration.
+ *
+ * Handle the feedback on @bfqq budget.  This is driven by the following
+ * principles:
+ *   - async queues get always the maximum budget value (their ability to
+ *     dispatch is limited by @bfqd->bfq_max_budget_async_rq).
+ *   - If @bfqq has been too idle we decrease its budget, as it is likely
+ *     to be more interested in latency than in throughput.
+ *   - If @bfqq took too much to consume its budget it is likely to be
+ *     seeky, so reset the budget to the default, in order to have all
+ *     the seeky queues to be charged for the same service, trying to
+ *     achieve fairness at least in the time domain among them.
+ *   - If @bfqq exhausted its budget treat it as a greedy reader, in
+ *     order to run it at full speed.
+ *   - If @bfqq expired due to lack of requests leave its budget untouched.
+ */
+static void __bfq_bfqq_recalc_budget(struct bfq_data *bfqd,
+				     struct bfq_queue *bfqq,
+				     enum bfqq_expiration reason)
+{
+	struct request *next_rq;
+	bfq_service_t budget, min_budget;
+
+	budget = bfqq->max_budget;
+	min_budget = bfq_min_budget(bfqd, bfqq);
+
+	BUG_ON(bfqq != bfqd->active_queue);
+
+	if (bfq_bfqq_sync(bfqq)) {
+		switch (reason) {
+		case BFQ_BFQQ_TOO_IDLE:
+			if (budget > min_budget + BFQ_BUDGET_STEP)
+				budget -= BFQ_BUDGET_STEP;
+			else
+				budget = min_budget;
+			break;
+		case BFQ_BFQQ_BUDGET_TIMEOUT:
+			budget = bfq_default_budget(bfqd, bfqq);
+			break;
+		case BFQ_BFQQ_BUDGET_EXHAUSTED:
+			budget = min(budget + 8 * BFQ_BUDGET_STEP,
+				     bfqd->bfq_max_budget);
+			break;
+		case BFQ_BFQQ_NO_MORE_REQUESTS:
+		default:
+			return;
+		}
+	} else
+		budget = bfqd->bfq_max_budget;
+
+	bfqq->max_budget = budget;
+
+	if (bfqq->budgets_assigned >= 194 && bfqd->bfq_user_max_budget == 0 &&
+	    bfqq->max_budget > bfqd->bfq_max_budget)
+		bfqq->max_budget = bfqd->bfq_max_budget;
+
+	/*
+	 * Make sure that we have enough budget for the next request.
+	 * Since the finish time of the bfqq must be kept in sync with
+	 * the budget, be sure to call __bfq_bfqq_expire() after the
+	 * update.
+	 */
+	next_rq = bfqq->next_rq;
+	if (next_rq != NULL)
+		bfqq->entity.budget = max(bfqq->max_budget,
+					  next_rq->hard_nr_sectors);
+	bfq_log_bfqq(bfqd, bfqq, "budget=%lu (%d)", bfqq->entity.budget,
+		     bfq_bfqq_sync(bfqq));
+}
+
+static bfq_service_t bfq_calc_max_budget(u64 peak_rate, u64 timeout)
+{
+	bfq_service_t max_budget;
+
+	/*
+	 * The max_budget calculated when autotuning is equal to the
+	 * amount of sectors transfered in 0.75 * timeout_sync at the
+	 * estimated peak rate.
+	 */
+	max_budget = (bfq_service_t)(peak_rate * 1000 *
+				     timeout >> BFQ_RATE_SHIFT);
+	max_budget -= max_budget / 4;
+
+	return max_budget;
+}
+
+static int bfq_update_peak_rate(struct bfq_data *bfqd, struct bfq_queue *bfqq,
+				int compensate)
+{
+	u64 bw, usecs, expected, timeout;
+	ktime_t delta;
+	int update = 0;
+
+	if (!bfq_bfqq_sync(bfqq) || bfq_bfqq_budget_new(bfqq))
+		return 0;
+
+	delta = compensate ? bfqd->last_idling_start : ktime_get();
+	delta = ktime_sub(delta, bfqd->last_budget_start);
+	usecs = ktime_to_us(delta);
+
+	/* Don't trust short/unrealistic values. */
+	if (usecs < 100 || usecs >= LONG_MAX)
+		return 0;
+
+	/*
+	 * Calculate the bandwidth for the last slice.  We use a 64 bit
+	 * value to store the peak rate, in sectors per usec in fixed
+	 * point math.  We do so to have enough precision in the estimate
+	 * and to avoid overflows.
+	 */
+	bw = (u64)bfqq->entity.service << BFQ_RATE_SHIFT;
+	do_div(bw, (unsigned long)usecs);
+
+	timeout = jiffies_to_msecs(bfqd->bfq_timeout[SYNC]);
+
+	/*
+	 * Use only long (> 20ms) intervals to filter out spikes for
+	 * the peak rate estimation.
+	 */
+	if (usecs > 20000) {
+		if (bw > bfqd->peak_rate) {
+			bfqd->peak_rate = bw;
+			update = 1;
+			bfq_log(bfqd, "peak_rate=%llu", bw);
+		}
+
+		update |= bfqd->peak_rate_samples == BFQ_PEAK_RATE_SAMPLES - 1;
+
+		if (bfqd->peak_rate_samples < BFQ_PEAK_RATE_SAMPLES)
+			bfqd->peak_rate_samples++;
+
+		if (bfqd->peak_rate_samples == BFQ_PEAK_RATE_SAMPLES &&
+		    update && bfqd->bfq_user_max_budget == 0) {
+			bfqd->bfq_max_budget =
+				bfq_calc_max_budget(bfqd->peak_rate, timeout);
+			bfq_log(bfqd, "max_budget=%lu", bfqd->bfq_max_budget);
+		}
+	}
+
+	/*
+	 * A process is considered ``slow'' (i.e., seeky, so that we
+	 * cannot treat it fairly in the service domain, as it would
+	 * slow down too much the other processes) if, when a slice
+	 * ends for whatever reason, it has received service at a
+	 * rate that would not be high enough to complete the budget
+	 * before the budget timeout expiration.
+	 */
+	expected = bw * 1000 * timeout >> BFQ_RATE_SHIFT;
+
+	return expected > bfqq->entity.budget;
+}
+
+/*
+ * bfq_bfqq_expire - expire a queue.
+ * @bfqd: device owning the queue.
+ * @bfqq: the queue to expire.
+ * @compensate: if true, compensate for the time spent idling.
+ * @reason: the reason causing the expiration.
+ *
+ * The behavior is the following: when a queue expires because it has
+ * been idling for too much we sync its finish time with the service
+ * received and decrease its budget.  If @bfqq expires due to budget
+ * exhaustion we increase its budget and sync its finish time.
+ * If @bfqq expires due to budget timeout we do not sync its finish time
+ * to avoid seeky queues to take too much disk time; instead we charge
+ * it the maximum budget value.  Using the max budget value for all the
+ * queues that expire due to budget timeout has the effect of using the
+ * WF2Q+ scheduler to assign timeslices to those queues, without violating
+ * the service domain guarantees for well-behaved queues.
+ */
+static void bfq_bfqq_expire(struct bfq_data *bfqd,
+			    struct bfq_queue *bfqq,
+			    int compensate,
+			    enum bfqq_expiration reason)
+{
+	int slow;
+
+	slow = bfq_update_peak_rate(bfqd, bfqq, compensate);
+
+	/*
+	 * Treat slow (i.e., seeky) traffic as timed out, to not favor
+	 * it over sequential traffic (a seeky queue consumes less budget,
+	 * so it would receive smaller timestamps wrt a sequential one
+	 * when an idling timer fires).
+	 */
+	if (slow && reason == BFQ_BFQQ_TOO_IDLE)
+		reason = BFQ_BFQQ_BUDGET_TIMEOUT;
+
+	if (reason == BFQ_BFQQ_BUDGET_TIMEOUT || !bfq_bfqq_sync(bfqq))
+		bfq_bfqq_charge_full_budget(bfqq);
+
+	bfq_log_bfqq(bfqd, bfqq, "expire (%d, %d)", reason, slow);
+
+	__bfq_bfqq_recalc_budget(bfqd, bfqq, reason);
+	__bfq_bfqq_expire(bfqd, bfqq);
+}
+
+static int bfq_bfqq_budget_timeout(struct bfq_queue *bfqq)
+{
+	if (bfq_bfqq_budget_new(bfqq))
+		return 0;
+
+	if (time_before(jiffies, bfqq->budget_timeout))
+		return 0;
+
+	return 1;
+}
+
+/*
+ * Select a queue for service.  If we have a current active queue,
+ * check whether to continue servicing it, or retrieve and set a new one.
+ */
+static struct bfq_queue *bfq_select_queue(struct bfq_data *bfqd)
+{
+	struct bfq_queue *bfqq;
+	struct request *next_rq;
+	enum bfqq_expiration reason = BFQ_BFQQ_BUDGET_TIMEOUT;
+
+	bfqq = bfqd->active_queue;
+	if (bfqq == NULL)
+		goto new_queue;
+
+	if (bfq_bfqq_budget_timeout(bfqq)) {
+		bfq_bfqq_charge_full_budget(bfqq);
+		goto expire;
+	}
+
+	next_rq = bfqq->next_rq;
+	/*
+	 * If bfqq has requests queued and it has enough budget left to
+	 * serve them, keep the queue, otherwise expire it.
+	 */
+	if (next_rq != NULL) {
+		if (next_rq->hard_nr_sectors > bfq_bfqq_budget_left(bfqq)) {
+			reason = BFQ_BFQQ_BUDGET_EXHAUSTED;
+			goto expire;
+		} else
+			goto keep_queue;
+	}
+
+	/*
+	 * No requests pending.  If the active queue still has requests in
+	 * flight or is idling for a new request, allow either of these
+	 * conditions to happen (or time out) before selecting a new queue.
+	 */
+	if (timer_pending(&bfqd->idle_slice_timer) ||
+	    (bfqq->dispatched != 0 && bfq_bfqq_idle_window(bfqq))) {
+		bfqq = NULL;
+		goto keep_queue;
+	}
+
+	reason = BFQ_BFQQ_NO_MORE_REQUESTS;
+expire:
+	bfq_bfqq_expire(bfqd, bfqq, 0, reason);
+new_queue:
+	bfqq = bfq_set_active_queue(bfqd);
+keep_queue:
+	return bfqq;
+}
+
+/*
+ * Dispatch some requests from bfqq, moving them to the request queue
+ * dispatch list.
+ */
+static int __bfq_dispatch_requests(struct bfq_data *bfqd,
+				   struct bfq_queue *bfqq,
+				   int max_dispatch)
+{
+	int dispatched = 0;
+
+	BUG_ON(RB_EMPTY_ROOT(&bfqq->sort_list));
+
+	do {
+		struct request *rq;
+
+		/* Follow expired path, else get first next available. */
+		rq = bfq_check_fifo(bfqq);
+		if (rq == NULL)
+			rq = bfqq->next_rq;
+
+		if (rq->hard_nr_sectors > bfq_bfqq_budget_left(bfqq)) {
+			/*
+			 * Expire the queue for budget exhaustion, and
+			 * make sure that the next act_budget is enough
+			 * to serve the next request, even if it comes
+			 * from the fifo expired path.
+			 */
+			bfqq->next_rq = rq;
+			goto expire;
+		}
+
+		/* Finally, insert request into driver dispatch list. */
+		bfq_bfqq_served(bfqq, rq->hard_nr_sectors);
+		bfq_dispatch_insert(bfqd->queue, rq);
+
+		dispatched++;
+
+		if (bfqd->active_cic == NULL) {
+			atomic_inc(&RQ_CIC(rq)->ioc->refcount);
+			bfqd->active_cic = RQ_CIC(rq);
+		}
+
+		if (RB_EMPTY_ROOT(&bfqq->sort_list))
+			break;
+	} while (dispatched < max_dispatch);
+
+	if (bfqd->busy_queues > 1 && ((!bfq_bfqq_sync(bfqq) &&
+	    dispatched >= bfqd->bfq_max_budget_async_rq) ||
+	    bfq_class_idle(bfqq)))
+		goto expire;
+
+	return dispatched;
+
+expire:
+	bfq_bfqq_expire(bfqd, bfqq, 0, BFQ_BFQQ_BUDGET_EXHAUSTED);
+	return dispatched;
+}
+
+static int __bfq_forced_dispatch_bfqq(struct bfq_queue *bfqq)
+{
+	int dispatched = 0;
+
+	while (bfqq->next_rq != NULL) {
+		bfq_dispatch_insert(bfqq->bfqd->queue, bfqq->next_rq);
+		dispatched++;
+	}
+
+	BUG_ON(!list_empty(&bfqq->fifo));
+	return dispatched;
+}
+
+/*
+ * Drain our current requests.  Used for barriers and when switching
+ * io schedulers on-the-fly.
+ */
+static int bfq_forced_dispatch(struct bfq_data *bfqd)
+{
+	struct bfq_queue *bfqq, *n;
+	struct bfq_service_tree *st;
+	int dispatched = 0;
+
+	bfqq = bfqd->active_queue;
+	if (bfqq != NULL)
+		__bfq_bfqq_expire(bfqd, bfqq);
+
+	/*
+	 * Loop through classes, and be careful to leave the scheduler
+	 * in a consistent state, as feedback mechanisms and vtime
+	 * updates cannot be disabled during the process.
+	 */
+	list_for_each_entry_safe(bfqq, n, &bfqd->active_list, bfqq_list) {
+		st = bfq_entity_service_tree(&bfqq->entity);
+
+		dispatched += __bfq_forced_dispatch_bfqq(bfqq);
+		bfqq->max_budget = bfq_default_budget(bfqd, bfqq);
+
+		bfq_forget_idle(st);
+	}
+
+	BUG_ON(bfqd->busy_queues != 0);
+
+	return dispatched;
+}
+
+static int bfq_dispatch_requests(struct request_queue *q, int force)
+{
+	struct bfq_data *bfqd = q->elevator->elevator_data;
+	struct bfq_queue *bfqq;
+	int dispatched;
+
+	if (bfqd->busy_queues == 0)
+		return 0;
+
+	if (unlikely(force))
+		return bfq_forced_dispatch(bfqd);
+
+	dispatched = 0;
+	while ((bfqq = bfq_select_queue(bfqd)) != NULL) {
+		int max_dispatch;
+
+		max_dispatch = bfqd->bfq_quantum;
+		if (bfq_class_idle(bfqq))
+			max_dispatch = 1;
+
+		if (!bfq_bfqq_sync(bfqq))
+			max_dispatch = bfqd->bfq_max_budget_async_rq;
+
+		if (bfqq->dispatched >= max_dispatch) {
+			if (bfqd->busy_queues > 1)
+				break;
+			if (bfqq->dispatched >= 4 * max_dispatch)
+				break;
+		}
+
+		if (bfqd->sync_flight != 0 && !bfq_bfqq_sync(bfqq))
+			break;
+
+		bfq_clear_bfqq_wait_request(bfqq);
+		BUG_ON(timer_pending(&bfqd->idle_slice_timer));
+
+		dispatched += __bfq_dispatch_requests(bfqd, bfqq, max_dispatch);
+	}
+
+	bfq_log(bfqd, "dispatched=%d", dispatched);
+	return dispatched;
+}
+
+/*
+ * Task holds one reference to the queue, dropped when task exits.  Each rq
+ * in-flight on this queue also holds a reference, dropped when rq is freed.
+ *
+ * Queue lock must be held here.
+ */
+static void bfq_put_queue(struct bfq_queue *bfqq)
+{
+	struct bfq_data *bfqd = bfqq->bfqd;
+
+	BUG_ON(atomic_read(&bfqq->ref) <= 0);
+
+	if (!atomic_dec_and_test(&bfqq->ref))
+		return;
+
+	BUG_ON(rb_first(&bfqq->sort_list) != NULL);
+	BUG_ON(bfqq->allocated[READ] + bfqq->allocated[WRITE] != 0);
+	BUG_ON(bfqq->entity.tree != NULL);
+	BUG_ON(bfq_bfqq_busy(bfqq));
+	BUG_ON(bfqd->active_queue == bfqq);
+
+	bfq_log_bfqq(bfqd, bfqq, "freed");
+
+	kmem_cache_free(bfq_pool, bfqq);
+}
+
+static void bfq_exit_bfqq(struct bfq_data *bfqd, struct bfq_queue *bfqq)
+{
+	if (bfqq == bfqd->active_queue) {
+		__bfq_bfqq_expire(bfqd, bfqq);
+		bfq_schedule_dispatch(bfqd);
+	}
+
+	bfq_put_queue(bfqq);
+}
+
+/*
+ * Update the entity prio values; note that the new values will not
+ * be used until the next (re)activation.
+ */
+static void bfq_init_prio_data(struct bfq_queue *bfqq, struct io_context *ioc)
+{
+	struct task_struct *tsk = current;
+	int ioprio_class;
+
+	if (!bfq_bfqq_prio_changed(bfqq))
+		return;
+
+	ioprio_class = IOPRIO_PRIO_CLASS(ioc->ioprio);
+	switch (ioprio_class) {
+	default:
+		printk(KERN_ERR "bfq: bad prio %x\n", ioprio_class);
+	case IOPRIO_CLASS_NONE:
+		/*
+		 * no prio set, inherit CPU scheduling settings
+		 */
+		bfqq->entity.new_ioprio = task_nice_ioprio(tsk);
+		bfqq->entity.new_ioprio_class = task_nice_ioclass(tsk);
+		break;
+	case IOPRIO_CLASS_RT:
+		bfqq->entity.new_ioprio = task_ioprio(ioc);
+		bfqq->entity.new_ioprio_class = IOPRIO_CLASS_RT;
+		break;
+	case IOPRIO_CLASS_BE:
+		bfqq->entity.new_ioprio = task_ioprio(ioc);
+		bfqq->entity.new_ioprio_class = IOPRIO_CLASS_BE;
+		break;
+	case IOPRIO_CLASS_IDLE:
+		bfqq->entity.new_ioprio_class = IOPRIO_CLASS_IDLE;
+		bfqq->entity.new_ioprio = 7;
+		bfq_clear_bfqq_idle_window(bfqq);
+		break;
+	}
+
+	bfqq->entity.ioprio_changed = 1;
+
+	/*
+	 * keep track of original prio settings in case we have to temporarily
+	 * elevate the priority of this queue
+	 */
+	bfqq->org_ioprio = bfqq->entity.new_ioprio;
+	bfqq->org_ioprio_class = bfqq->entity.new_ioprio_class;
+	bfq_clear_bfqq_prio_changed(bfqq);
+}
+
+static void bfq_changed_ioprio(struct io_context *ioc,
+			       struct cfq_io_context *cic)
+{
+	struct bfq_data *bfqd;
+	struct bfq_queue *bfqq, *new_bfqq;
+	struct bfq_group *bfqg;
+	unsigned long uninitialized_var(flags);
+
+	bfqd = bfq_get_bfqd_locked(&cic->key, &flags);
+	if (unlikely(bfqd == NULL))
+		return;
+
+	bfqq = cic->cfqq[ASYNC];
+	if (bfqq != NULL) {
+		bfqg = container_of(bfqq->entity.sched_data, struct bfq_group,
+				    sched_data);
+		new_bfqq = bfq_get_queue(bfqd, bfqg, ASYNC, cic->ioc,
+					 GFP_ATOMIC);
+		if (new_bfqq != NULL) {
+			cic->cfqq[ASYNC] = new_bfqq;
+			bfq_put_queue(bfqq);
+		}
+	}
+
+	bfqq = cic->cfqq[SYNC];
+	if (bfqq != NULL)
+		bfq_mark_bfqq_prio_changed(bfqq);
+
+	bfq_put_bfqd_unlock(bfqd, &flags);
+}
+
+static struct bfq_queue *bfq_find_alloc_queue(struct bfq_data *bfqd,
+					      struct bfq_group *bfqg,
+					      int is_sync,
+					      struct io_context *ioc,
+					      gfp_t gfp_mask)
+{
+	struct bfq_queue *bfqq, *new_bfqq = NULL;
+	struct cfq_io_context *cic;
+
+retry:
+	cic = bfq_cic_lookup(bfqd, ioc);
+	/* cic always exists here */
+	bfqq = cic_to_bfqq(cic, is_sync);
+
+	if (bfqq == NULL) {
+		if (new_bfqq != NULL) {
+			bfqq = new_bfqq;
+			new_bfqq = NULL;
+		} else if (gfp_mask & __GFP_WAIT) {
+			/*
+			 * Inform the allocator of the fact that we will
+			 * just repeat this allocation if it fails, to allow
+			 * the allocator to do whatever it needs to attempt to
+			 * free memory.
+			 */
+			spin_unlock_irq(bfqd->queue->queue_lock);
+			new_bfqq = kmem_cache_alloc_node(bfq_pool,
+					gfp_mask | __GFP_NOFAIL | __GFP_ZERO,
+					bfqd->queue->node);
+			spin_lock_irq(bfqd->queue->queue_lock);
+			goto retry;
+		} else {
+			bfqq = kmem_cache_alloc_node(bfq_pool,
+					gfp_mask | __GFP_ZERO,
+					bfqd->queue->node);
+			if (bfqq == NULL)
+				goto out;
+		}
+
+		RB_CLEAR_NODE(&bfqq->entity.rb_node);
+		INIT_LIST_HEAD(&bfqq->fifo);
+
+		atomic_set(&bfqq->ref, 0);
+		bfqq->bfqd = bfqd;
+
+		bfq_mark_bfqq_prio_changed(bfqq);
+
+		bfq_init_prio_data(bfqq, ioc);
+		bfq_init_entity(&bfqq->entity, bfqg);
+
+		if (is_sync) {
+			if (!bfq_class_idle(bfqq))
+				bfq_mark_bfqq_idle_window(bfqq);
+			bfq_mark_bfqq_sync(bfqq);
+		}
+		bfqq->max_budget = bfq_default_budget(bfqd, bfqq);
+		bfqq->pid = current->pid;
+
+		bfq_log_bfqq(bfqd, bfqq, "allocated");
+	}
+
+	if (new_bfqq != NULL)
+		kmem_cache_free(bfq_pool, new_bfqq);
+
+out:
+	WARN_ON((gfp_mask & __GFP_WAIT) && bfqq == NULL);
+	return bfqq;
+}
+
+static struct bfq_queue **bfq_async_queue_prio(struct bfq_data *bfqd,
+					       struct bfq_group *bfqg,
+					       int ioprio_class, int ioprio)
+{
+	switch (ioprio_class) {
+	case IOPRIO_CLASS_RT:
+		return &bfqg->async_bfqq[0][ioprio];
+	case IOPRIO_CLASS_BE:
+		return &bfqg->async_bfqq[1][ioprio];
+	case IOPRIO_CLASS_IDLE:
+		return &bfqg->async_idle_bfqq;
+	default:
+		BUG();
+	}
+}
+
+static struct bfq_queue *bfq_get_queue(struct bfq_data *bfqd,
+				       struct bfq_group *bfqg, int is_sync,
+				       struct io_context *ioc, gfp_t gfp_mask)
+{
+	const int ioprio = task_ioprio(ioc);
+	const int ioprio_class = task_ioprio_class(ioc);
+	struct bfq_queue **async_bfqq = NULL;
+	struct bfq_queue *bfqq = NULL;
+
+	if (!is_sync) {
+		async_bfqq = bfq_async_queue_prio(bfqd, bfqg, ioprio_class,
+						  ioprio);
+		bfqq = *async_bfqq;
+	}
+
+	if (bfqq == NULL) {
+		bfqq = bfq_find_alloc_queue(bfqd, bfqg, is_sync, ioc, gfp_mask);
+		if (bfqq == NULL)
+			return NULL;
+	}
+
+	/*
+	 * pin the queue now that it's allocated, scheduler exit will prune it
+	 */
+	if (!is_sync && *async_bfqq == NULL) {
+		atomic_inc(&bfqq->ref);
+		*async_bfqq = bfqq;
+	}
+
+	atomic_inc(&bfqq->ref);
+	return bfqq;
+}
+
+static void bfq_update_io_thinktime(struct bfq_data *bfqd,
+				    struct cfq_io_context *cic)
+{
+	unsigned long elapsed = jiffies - cic->last_end_request;
+	unsigned long ttime = min(elapsed, 2UL * bfqd->bfq_slice_idle);
+
+	cic->ttime_samples = (7*cic->ttime_samples + 256) / 8;
+	cic->ttime_total = (7*cic->ttime_total + 256*ttime) / 8;
+	cic->ttime_mean = (cic->ttime_total + 128) / cic->ttime_samples;
+}
+
+static void bfq_update_io_seektime(struct bfq_data *bfqd,
+				   struct bfq_queue *bfqq,
+				   struct cfq_io_context *cic,
+				   struct request *rq)
+{
+	sector_t sdist;
+	u64 total;
+
+	if (cic->last_request_pos < rq->sector)
+		sdist = rq->sector - cic->last_request_pos;
+	else
+		sdist = cic->last_request_pos - rq->sector;
+
+	/*
+	 * Don't allow the seek distance to get too large from the
+	 * odd fragment, pagein, etc.
+	 */
+	if (cic->seek_samples == 0) /* first request, not really a seek */
+		sdist = 0;
+	else if (cic->seek_samples <= 60) /* second&third seek */
+		sdist = min(sdist, (cic->seek_mean * 4) + 2*1024*1024);
+	else
+		sdist = min(sdist, (cic->seek_mean * 4)	+ 2*1024*64);
+
+	cic->seek_samples = (7*cic->seek_samples + 256) / 8;
+	cic->seek_total = (7*cic->seek_total + (u64)256*sdist) / 8;
+	total = cic->seek_total + (cic->seek_samples/2);
+	do_div(total, cic->seek_samples);
+	cic->seek_mean = (sector_t)total;
+
+	bfq_log_bfqq(bfqd, bfqq, "dist=%lu mean=%lu", sdist, cic->seek_mean);
+}
+
+/*
+ * Disable idle window if the process thinks too long or seeks so much that
+ * it doesn't matter.
+ */
+static void bfq_update_idle_window(struct bfq_data *bfqd,
+				   struct bfq_queue *bfqq,
+				   struct cfq_io_context *cic)
+{
+	int enable_idle;
+
+	/* Don't idle for async or idle io prio class. */
+	if (!bfq_bfqq_sync(bfqq) || bfq_class_idle(bfqq))
+		return;
+
+	enable_idle = bfq_bfqq_idle_window(bfqq);
+
+	if (atomic_read(&cic->ioc->nr_tasks) == 0 ||
+	    bfqd->bfq_slice_idle == 0 || (bfqd->hw_tag && CIC_SEEKY(cic)))
+		enable_idle = 0;
+	else if (bfq_sample_valid(cic->ttime_samples)) {
+		if (cic->ttime_mean > bfqd->bfq_slice_idle)
+			enable_idle = 0;
+		else
+			enable_idle = 1;
+	}
+
+	if (enable_idle)
+		bfq_mark_bfqq_idle_window(bfqq);
+	else
+		bfq_clear_bfqq_idle_window(bfqq);
+
+	bfq_log_bfqq(bfqd, bfqq, "idle_window=%d (%d)",
+		     enable_idle, CIC_SEEKY(cic));
+}
+
+/*
+ * Called when a new fs request (rq) is added to bfqq.  Check if there's
+ * something we should do about it.
+ */
+static void bfq_rq_enqueued(struct bfq_data *bfqd, struct bfq_queue *bfqq,
+			    struct request *rq)
+{
+	struct cfq_io_context *cic = RQ_CIC(rq);
+
+	if (rq_is_meta(rq))
+		bfqq->meta_pending++;
+
+	bfq_update_io_thinktime(bfqd, cic);
+	bfq_update_io_seektime(bfqd, bfqq, cic, rq);
+	bfq_update_idle_window(bfqd, bfqq, cic);
+
+	cic->last_request_pos = rq->sector + rq->nr_sectors;
+
+	if (bfqq == bfqd->active_queue && bfq_bfqq_wait_request(bfqq)) {
+		/*
+		 * If we are waiting for a request for this queue, let it rip
+		 * immediately and flag that we must not expire this queue
+		 * just now.
+		 */
+		bfq_clear_bfqq_wait_request(bfqq);
+		del_timer(&bfqd->idle_slice_timer);
+		blk_start_queueing(bfqd->queue);
+	}
+}
+
+static void bfq_insert_request(struct request_queue *q, struct request *rq)
+{
+	struct bfq_data *bfqd = q->elevator->elevator_data;
+	struct bfq_queue *bfqq = RQ_BFQQ(rq);
+
+	bfq_init_prio_data(bfqq, RQ_CIC(rq)->ioc);
+
+	bfq_add_rq_rb(rq);
+
+	list_add_tail(&rq->queuelist, &bfqq->fifo);
+
+	bfq_rq_enqueued(bfqd, bfqq, rq);
+}
+
+static void bfq_update_hw_tag(struct bfq_data *bfqd)
+{
+	bfqd->max_rq_in_driver = max(bfqd->max_rq_in_driver,
+				     bfqd->rq_in_driver);
+
+	/*
+	 * This sample is valid if the number of outstanding requests
+	 * is large enough to allow a queueing behavior.  Note that the
+	 * sum is not exact, as it's not taking into account deactivated
+	 * requests.
+	 */
+	if (bfqd->rq_in_driver + bfqd->queued < BFQ_HW_QUEUE_THRESHOLD)
+		return;
+
+	if (bfqd->hw_tag_samples++ < BFQ_HW_QUEUE_SAMPLES)
+		return;
+
+	bfqd->hw_tag = bfqd->max_rq_in_driver > BFQ_HW_QUEUE_THRESHOLD;
+	bfqd->max_rq_in_driver = 0;
+	bfqd->hw_tag_samples = 0;
+}
+
+static void bfq_completed_request(struct request_queue *q, struct request *rq)
+{
+	struct bfq_queue *bfqq = RQ_BFQQ(rq);
+	struct bfq_data *bfqd = bfqq->bfqd;
+	const int sync = rq_is_sync(rq);
+
+	bfq_log_bfqq(bfqd, bfqq, "complete");
+
+	bfq_update_hw_tag(bfqd);
+
+	WARN_ON(!bfqd->rq_in_driver);
+	WARN_ON(!bfqq->dispatched);
+	bfqd->rq_in_driver--;
+	bfqq->dispatched--;
+
+	if (bfq_bfqq_sync(bfqq))
+		bfqd->sync_flight--;
+
+	if (sync)
+		RQ_CIC(rq)->last_end_request = jiffies;
+
+	/*
+	 * If this is the active queue, check if it needs to be expired,
+	 * or if we want to idle in case it has no pending requests.
+	 */
+	if (bfqd->active_queue == bfqq) {
+		if (bfq_bfqq_budget_new(bfqq))
+			bfq_set_budget_timeout(bfqd);
+
+		if (bfq_bfqq_budget_timeout(bfqq))
+			bfq_bfqq_expire(bfqd, bfqq, 0, BFQ_BFQQ_BUDGET_TIMEOUT);
+		else if (sync && bfqd->rq_in_driver == 0 &&
+			 RB_EMPTY_ROOT(&bfqq->sort_list))
+			bfq_arm_slice_timer(bfqd);
+	}
+
+	if (!bfqd->rq_in_driver)
+		bfq_schedule_dispatch(bfqd);
+}
+
+/*
+ * We temporarily boost lower priority queues if they are holding fs exclusive
+ * resources.  They are boosted to normal prio (CLASS_BE/4).
+ */
+static void bfq_prio_boost(struct bfq_queue *bfqq)
+{
+	if (has_fs_excl()) {
+		/*
+		 * boost idle prio on transactions that would lock out other
+		 * users of the filesystem
+		 */
+		if (bfq_class_idle(bfqq))
+			bfqq->entity.new_ioprio_class = IOPRIO_CLASS_BE;
+		if (bfqq->entity.new_ioprio > IOPRIO_NORM)
+			bfqq->entity.new_ioprio = IOPRIO_NORM;
+	} else {
+		/*
+		 * check if we need to unboost the queue
+		 */
+		if (bfqq->entity.new_ioprio_class != bfqq->org_ioprio_class)
+			bfqq->entity.new_ioprio_class = bfqq->org_ioprio_class;
+		if (bfqq->entity.new_ioprio != bfqq->org_ioprio)
+			bfqq->entity.new_ioprio = bfqq->org_ioprio;
+	}
+}
+
+static inline int __bfq_may_queue(struct bfq_queue *bfqq)
+{
+	if (bfq_bfqq_wait_request(bfqq) && bfq_bfqq_must_alloc(bfqq)) {
+		bfq_clear_bfqq_must_alloc(bfqq);
+		return ELV_MQUEUE_MUST;
+	}
+
+	return ELV_MQUEUE_MAY;
+}
+
+static int bfq_may_queue(struct request_queue *q, int rw)
+{
+	struct bfq_data *bfqd = q->elevator->elevator_data;
+	struct task_struct *tsk = current;
+	struct cfq_io_context *cic;
+	struct bfq_queue *bfqq;
+
+	/*
+	 * Don't force setup of a queue from here, as a call to may_queue
+	 * does not necessarily imply that a request actually will be queued.
+	 * so just lookup a possibly existing queue, or return 'may queue'
+	 * if that fails.
+	 */
+	cic = bfq_cic_lookup(bfqd, tsk->io_context);
+	if (cic == NULL)
+		return ELV_MQUEUE_MAY;
+
+	bfqq = cic_to_bfqq(cic, rw & REQ_RW_SYNC);
+	if (bfqq != NULL) {
+		bfq_init_prio_data(bfqq, cic->ioc);
+		bfq_prio_boost(bfqq);
+
+		return __bfq_may_queue(bfqq);
+	}
+
+	return ELV_MQUEUE_MAY;
+}
+
+/*
+ * queue lock held here
+ */
+static void bfq_put_request(struct request *rq)
+{
+	struct bfq_queue *bfqq = RQ_BFQQ(rq);
+
+	if (bfqq != NULL) {
+		const int rw = rq_data_dir(rq);
+
+		BUG_ON(!bfqq->allocated[rw]);
+		bfqq->allocated[rw]--;
+
+		put_io_context(RQ_CIC(rq)->ioc);
+
+		rq->elevator_private = NULL;
+		rq->elevator_private2 = NULL;
+
+		bfq_put_queue(bfqq);
+	}
+}
+
+/*
+ * Allocate bfq data structures associated with this request.
+ */
+static int bfq_set_request(struct request_queue *q, struct request *rq,
+			   gfp_t gfp_mask)
+{
+	struct bfq_data *bfqd = q->elevator->elevator_data;
+	struct cfq_io_context *cic;
+	const int rw = rq_data_dir(rq);
+	const int is_sync = rq_is_sync(rq);
+	struct bfq_queue *bfqq;
+	struct bfq_group *bfqg;
+	unsigned long flags;
+
+	might_sleep_if(gfp_mask & __GFP_WAIT);
+
+	cic = bfq_get_io_context(bfqd, gfp_mask);
+
+	spin_lock_irqsave(q->queue_lock, flags);
+
+	if (cic == NULL)
+		goto queue_fail;
+
+	bfqg = bfq_cic_update_cgroup(cic);
+
+	bfqq = cic_to_bfqq(cic, is_sync);
+	if (bfqq == NULL) {
+		bfqq = bfq_get_queue(bfqd, bfqg, is_sync, cic->ioc, gfp_mask);
+		if (bfqq == NULL)
+			goto queue_fail;
+
+		cic_set_bfqq(cic, bfqq, is_sync);
+	}
+
+	bfqq->allocated[rw]++;
+	atomic_inc(&bfqq->ref);
+
+	spin_unlock_irqrestore(q->queue_lock, flags);
+
+	rq->elevator_private = cic;
+	rq->elevator_private2 = bfqq;
+
+	return 0;
+
+queue_fail:
+	if (cic != NULL)
+		put_io_context(cic->ioc);
+
+	bfq_schedule_dispatch(bfqd);
+	spin_unlock_irqrestore(q->queue_lock, flags);
+
+	return 1;
+}
+
+static void bfq_kick_queue(struct work_struct *work)
+{
+	struct bfq_data *bfqd =
+		container_of(work, struct bfq_data, unplug_work);
+	struct request_queue *q = bfqd->queue;
+	unsigned long flags;
+
+	spin_lock_irqsave(q->queue_lock, flags);
+	blk_start_queueing(q);
+	spin_unlock_irqrestore(q->queue_lock, flags);
+}
+
+/*
+ * Timer running if the active_queue is currently idling inside its time slice
+ */
+static void bfq_idle_slice_timer(unsigned long data)
+{
+	struct bfq_data *bfqd = (struct bfq_data *)data;
+	struct bfq_queue *bfqq;
+	unsigned long flags;
+	enum bfqq_expiration reason;
+
+	bfq_log(bfqd, "slice_timer expired");
+
+	spin_lock_irqsave(bfqd->queue->queue_lock, flags);
+
+	bfqq = bfqd->active_queue;
+	/*
+	 * Theoretical race here: active_queue can be NULL or different
+	 * from the queue that was idling if the timer handler spins on
+	 * the queue_lock and a new request arrives for the current
+	 * queue and there is a full dispatch cycle that changes the
+	 * active_queue.  This can hardly happen, but in the worst case
+	 * we just expire a queue too early.
+	 */
+	if (bfqq != NULL) {
+		reason = BFQ_BFQQ_TOO_IDLE;
+		if (bfq_bfqq_budget_timeout(bfqq))
+			reason = BFQ_BFQQ_BUDGET_TIMEOUT;
+
+		bfq_bfqq_expire(bfqd, bfqq, 1, reason);
+	}
+
+	bfq_schedule_dispatch(bfqd);
+
+	spin_unlock_irqrestore(bfqd->queue->queue_lock, flags);
+}
+
+static void bfq_shutdown_timer_wq(struct bfq_data *bfqd)
+{
+	del_timer_sync(&bfqd->idle_slice_timer);
+	kblockd_flush_work(&bfqd->unplug_work);
+}
+
+static inline void __bfq_put_async_bfqq(struct bfq_data *bfqd,
+					struct bfq_queue **bfqq_ptr)
+{
+	struct bfq_group *root_group = bfqd->root_group;
+	struct bfq_queue *bfqq = *bfqq_ptr;
+
+	if (bfqq != NULL) {
+		bfq_bfqq_move(bfqd, bfqq, &bfqq->entity, root_group);
+		bfq_put_queue(bfqq);
+		*bfqq_ptr = NULL;
+	}
+}
+
+/*
+ * Release all the bfqg references to its async queues.  If we are
+ * deallocating the group these queues may still contain requests, so
+ * we reparent them to the root cgroup (i.e., the only one that will
+ * exist for sure untill all the requests on a device are gone).
+ */
+static void bfq_put_async_queues(struct bfq_data *bfqd, struct bfq_group *bfqg)
+{
+	int i, j;
+
+	for (i = 0; i < 2; i++)
+		for (j = 0; j < IOPRIO_BE_NR; j++)
+			__bfq_put_async_bfqq(bfqd, &bfqg->async_bfqq[i][j]);
+
+	__bfq_put_async_bfqq(bfqd, &bfqg->async_idle_bfqq);
+}
+
+static void bfq_exit_queue(elevator_t *e)
+{
+	struct bfq_data *bfqd = e->elevator_data;
+	struct request_queue *q = bfqd->queue;
+	struct bfq_queue *bfqq, *n;
+	struct cfq_io_context *cic;
+
+	bfq_shutdown_timer_wq(bfqd);
+
+	spin_lock_irq(q->queue_lock);
+
+	while (!list_empty(&bfqd->cic_list)) {
+		cic = list_entry(bfqd->cic_list.next, struct cfq_io_context,
+				 queue_list);
+		__bfq_exit_single_io_context(bfqd, cic);
+	}
+
+	BUG_ON(bfqd->active_queue != NULL);
+	list_for_each_entry_safe(bfqq, n, &bfqd->idle_list, bfqq_list)
+		bfq_deactivate_bfqq(bfqd, bfqq, 0);
+
+	bfq_disconnect_groups(bfqd);
+	spin_unlock_irq(q->queue_lock);
+
+	bfq_shutdown_timer_wq(bfqd);
+
+	/* Wait for cic->key accessors to exit their grace periods. */
+	synchronize_rcu();
+
+	BUG_ON(timer_pending(&bfqd->idle_slice_timer));
+
+	bfq_free_root_group(bfqd);
+	kfree(bfqd);
+}
+
+static void *bfq_init_queue(struct request_queue *q)
+{
+	struct bfq_group *bfqg;
+	struct bfq_data *bfqd;
+
+	bfqd = kmalloc_node(sizeof(*bfqd), GFP_KERNEL | __GFP_ZERO, q->node);
+	if (bfqd == NULL)
+		return NULL;
+
+	INIT_LIST_HEAD(&bfqd->cic_list);
+
+	bfqd->queue = q;
+
+	bfqg = bfq_alloc_root_group(bfqd, q->node);
+	if (bfqg == NULL) {
+		kfree(bfqd);
+		return NULL;
+	}
+
+	bfqd->root_group = bfqg;
+
+	init_timer(&bfqd->idle_slice_timer);
+	bfqd->idle_slice_timer.function = bfq_idle_slice_timer;
+	bfqd->idle_slice_timer.data = (unsigned long)bfqd;
+
+	INIT_WORK(&bfqd->unplug_work, bfq_kick_queue);
+
+	INIT_LIST_HEAD(&bfqd->active_list);
+	INIT_LIST_HEAD(&bfqd->idle_list);
+
+	bfqd->hw_tag = 1;
+
+	bfqd->bfq_max_budget = bfq_max_budget;
+
+	bfqd->bfq_quantum = bfq_quantum;
+	bfqd->bfq_fifo_expire[0] = bfq_fifo_expire[0];
+	bfqd->bfq_fifo_expire[1] = bfq_fifo_expire[1];
+	bfqd->bfq_back_max = bfq_back_max;
+	bfqd->bfq_back_penalty = bfq_back_penalty;
+	bfqd->bfq_slice_idle = bfq_slice_idle;
+	bfqd->bfq_max_budget_async_rq = bfq_max_budget_async_rq;
+	bfqd->bfq_timeout[ASYNC] = bfq_timeout_async;
+	bfqd->bfq_timeout[SYNC] = bfq_timeout_sync;
+
+	return bfqd;
+}
+
+static void bfq_slab_kill(void)
+{
+	if (bfq_pool != NULL)
+		kmem_cache_destroy(bfq_pool);
+	if (bfq_ioc_pool != NULL)
+		kmem_cache_destroy(bfq_ioc_pool);
+}
+
+static int __init bfq_slab_setup(void)
+{
+	bfq_pool = KMEM_CACHE(bfq_queue, 0);
+	if (bfq_pool == NULL)
+		goto fail;
+
+	bfq_ioc_pool = kmem_cache_create("bfq_io_context",
+					 sizeof(struct cfq_io_context),
+					 __alignof__(struct cfq_io_context),
+					 0, NULL);
+	if (bfq_ioc_pool == NULL)
+		goto fail;
+
+	return 0;
+fail:
+	bfq_slab_kill();
+	return -ENOMEM;
+}
+
+static ssize_t bfq_var_show(unsigned int var, char *page)
+{
+	return sprintf(page, "%d\n", var);
+}
+
+static ssize_t bfq_var_store(unsigned int *var, const char *page, size_t count)
+{
+	char *p = (char *)page;
+
+	*var = simple_strtoul(p, &p, 10);
+	return count;
+}
+
+#define SHOW_FUNCTION(__FUNC, __VAR, __CONV)				\
+static ssize_t __FUNC(elevator_t *e, char *page)			\
+{									\
+	struct bfq_data *bfqd = e->elevator_data;			\
+	unsigned int __data = __VAR;					\
+	if (__CONV)							\
+		__data = jiffies_to_msecs(__data);			\
+	return bfq_var_show(__data, (page));				\
+}
+SHOW_FUNCTION(bfq_quantum_show, bfqd->bfq_quantum, 0);
+SHOW_FUNCTION(bfq_fifo_expire_sync_show, bfqd->bfq_fifo_expire[1], 1);
+SHOW_FUNCTION(bfq_fifo_expire_async_show, bfqd->bfq_fifo_expire[0], 1);
+SHOW_FUNCTION(bfq_back_seek_max_show, bfqd->bfq_back_max, 0);
+SHOW_FUNCTION(bfq_back_seek_penalty_show, bfqd->bfq_back_penalty, 0);
+SHOW_FUNCTION(bfq_slice_idle_show, bfqd->bfq_slice_idle, 1);
+SHOW_FUNCTION(bfq_max_budget_show, bfqd->bfq_user_max_budget, 0);
+SHOW_FUNCTION(bfq_max_budget_async_rq_show, bfqd->bfq_max_budget_async_rq, 0);
+SHOW_FUNCTION(bfq_timeout_sync_show, bfqd->bfq_timeout[SYNC], 1);
+SHOW_FUNCTION(bfq_timeout_async_show, bfqd->bfq_timeout[ASYNC], 1);
+#undef SHOW_FUNCTION
+
+#define STORE_FUNCTION(__FUNC, __PTR, MIN, MAX, __CONV)			\
+static ssize_t __FUNC(elevator_t *e, const char *page, size_t count)	\
+{									\
+	struct bfq_data *bfqd = e->elevator_data;			\
+	unsigned int __data;						\
+	int ret = bfq_var_store(&__data, (page), count);		\
+	if (__data < (MIN))						\
+		__data = (MIN);						\
+	else if (__data > (MAX))					\
+		__data = (MAX);						\
+	if (__CONV)							\
+		*(__PTR) = msecs_to_jiffies(__data);			\
+	else								\
+		*(__PTR) = __data;					\
+	return ret;							\
+}
+STORE_FUNCTION(bfq_quantum_store, &bfqd->bfq_quantum, 1, INT_MAX, 0);
+STORE_FUNCTION(bfq_fifo_expire_sync_store, &bfqd->bfq_fifo_expire[1], 1,
+		INT_MAX, 1);
+STORE_FUNCTION(bfq_fifo_expire_async_store, &bfqd->bfq_fifo_expire[0], 1,
+		INT_MAX, 1);
+STORE_FUNCTION(bfq_back_seek_max_store, &bfqd->bfq_back_max, 0, INT_MAX, 0);
+STORE_FUNCTION(bfq_back_seek_penalty_store, &bfqd->bfq_back_penalty, 1,
+		INT_MAX, 0);
+STORE_FUNCTION(bfq_slice_idle_store, &bfqd->bfq_slice_idle, 0, INT_MAX, 1);
+STORE_FUNCTION(bfq_max_budget_async_rq_store, &bfqd->bfq_max_budget_async_rq,
+		1, INT_MAX, 0);
+STORE_FUNCTION(bfq_timeout_async_store, &bfqd->bfq_timeout[ASYNC], 0,
+		INT_MAX, 1);
+#undef STORE_FUNCTION
+
+static inline bfq_service_t bfq_estimated_max_budget(struct bfq_data *bfqd)
+{
+	u64 timeout = jiffies_to_msecs(bfqd->bfq_timeout[SYNC]);
+
+	if (bfqd->peak_rate_samples >= BFQ_PEAK_RATE_SAMPLES)
+		return bfq_calc_max_budget(bfqd->peak_rate, timeout);
+	else
+		return bfq_max_budget;
+}
+
+static ssize_t bfq_max_budget_store(elevator_t *e, const char *page,
+				    size_t count)
+{
+	struct bfq_data *bfqd = e->elevator_data;
+	unsigned int __data;
+	int ret = bfq_var_store(&__data, (page), count);
+
+	if (__data == 0)
+		bfqd->bfq_max_budget = bfq_estimated_max_budget(bfqd);
+	else {
+		if (__data > INT_MAX)
+			__data = INT_MAX;
+		bfqd->bfq_max_budget = __data;
+	}
+
+	bfqd->bfq_user_max_budget = __data;
+
+	return ret;
+}
+
+static ssize_t bfq_timeout_sync_store(elevator_t *e, const char *page,
+				      size_t count)
+{
+	struct bfq_data *bfqd = e->elevator_data;
+	unsigned int __data;
+	int ret = bfq_var_store(&__data, (page), count);
+
+	if (__data < 1)
+		__data = 1;
+	else if (__data > INT_MAX)
+		__data = INT_MAX;
+
+	bfqd->bfq_timeout[SYNC] = msecs_to_jiffies(__data);
+	if (bfqd->bfq_user_max_budget == 0)
+		bfqd->bfq_max_budget = bfq_estimated_max_budget(bfqd);
+
+	return ret;
+}
+
+#define BFQ_ATTR(name) \
+	__ATTR(name, S_IRUGO|S_IWUSR, bfq_##name##_show, bfq_##name##_store)
+
+static struct elv_fs_entry bfq_attrs[] = {
+	BFQ_ATTR(quantum),
+	BFQ_ATTR(fifo_expire_sync),
+	BFQ_ATTR(fifo_expire_async),
+	BFQ_ATTR(back_seek_max),
+	BFQ_ATTR(back_seek_penalty),
+	BFQ_ATTR(slice_idle),
+	BFQ_ATTR(max_budget),
+	BFQ_ATTR(max_budget_async_rq),
+	BFQ_ATTR(timeout_sync),
+	BFQ_ATTR(timeout_async),
+	__ATTR_NULL
+};
+
+static struct elevator_type iosched_bfq = {
+	.ops = {
+		.elevator_merge_fn = 		bfq_merge,
+		.elevator_merged_fn =		bfq_merged_request,
+		.elevator_merge_req_fn =	bfq_merged_requests,
+		.elevator_allow_merge_fn =	bfq_allow_merge,
+		.elevator_dispatch_fn =		bfq_dispatch_requests,
+		.elevator_add_req_fn =		bfq_insert_request,
+		.elevator_activate_req_fn =	bfq_activate_request,
+		.elevator_deactivate_req_fn =	bfq_deactivate_request,
+		.elevator_queue_empty_fn =	bfq_queue_empty,
+		.elevator_completed_req_fn =	bfq_completed_request,
+		.elevator_former_req_fn =	elv_rb_former_request,
+		.elevator_latter_req_fn =	elv_rb_latter_request,
+		.elevator_set_req_fn =		bfq_set_request,
+		.elevator_put_req_fn =		bfq_put_request,
+		.elevator_may_queue_fn =	bfq_may_queue,
+		.elevator_init_fn =		bfq_init_queue,
+		.elevator_exit_fn =		bfq_exit_queue,
+		.trim =				bfq_free_io_context,
+	},
+	.elevator_attrs =	bfq_attrs,
+	.elevator_name =	"bfq",
+	.elevator_owner =	THIS_MODULE,
+};
+
+static int __init bfq_init(void)
+{
+	/*
+	 * can be 0 on HZ < 1000 setups
+	 */
+	if (bfq_slice_idle == 0)
+		bfq_slice_idle = 1;
+
+	if (bfq_timeout_async == 0)
+		bfq_timeout_async = 1;
+
+	if (bfq_slab_setup())
+		return -ENOMEM;
+
+	elv_register(&iosched_bfq);
+
+	return 0;
+}
+
+static void __exit bfq_exit(void)
+{
+	DECLARE_COMPLETION_ONSTACK(all_gone);
+	elv_unregister(&iosched_bfq);
+	bfq_ioc_gone = &all_gone;
+	/* bfq_ioc_gone's update must be visible before reading bfq_ioc_count */
+	smp_wmb();
+	if (elv_ioc_count_read(bfq_ioc_count) != 0)
+		wait_for_completion(&all_gone);
+	bfq_slab_kill();
+}
+
+module_init(bfq_init);
+module_exit(bfq_exit);
+
+MODULE_AUTHOR("Fabio Checconi, Paolo Valente");
+MODULE_LICENSE("GPL");
+MODULE_DESCRIPTION("Budget Fair Queueing IO scheduler");
diff -Nru linux-source-2.6.28/block/bfq-sched.c linux-source-2.6.28-gs-bfq/block/bfq-sched.c
--- linux-source-2.6.28/block/bfq-sched.c	1970-01-01 01:00:00.000000000 +0100
+++ linux-source-2.6.28-gs-bfq/block/bfq-sched.c	2009-04-28 12:01:06.000000000 +0200
@@ -0,0 +1,950 @@
+/*
+ * BFQ: Hierarchical B-WF2Q+ scheduler.
+ *
+ * Based on ideas and code from CFQ:
+ * Copyright (C) 2003 Jens Axboe <axboe@kernel.dk>
+ *
+ * Copyright (C) 2008 Fabio Checconi <fabio@gandalf.sssup.it>
+ *		      Paolo Valente <paolo.valente@unimore.it>
+ */
+
+#ifdef CONFIG_CGROUP_BFQIO
+#define for_each_entity(entity)	\
+	for (; entity != NULL; entity = entity->parent)
+
+#define for_each_entity_safe(entity, parent) \
+	for (; entity && ({ parent = entity->parent; 1; }); entity = parent)
+
+static struct bfq_entity *bfq_lookup_next_entity(struct bfq_sched_data *sd,
+						 int extract);
+
+static int bfq_update_next_active(struct bfq_sched_data *sd)
+{
+	struct bfq_group *bfqg;
+	struct bfq_entity *entity, *next_active;
+
+	if (sd->active_entity != NULL)
+		/* will update/requeue at the end of service */
+		return 0;
+
+	/*
+	 * NOTE: this can be improved in may ways, such as returning
+	 * 1 (and thus propagating upwards the update) only when the
+	 * budget changes, or caching the bfqq that will be scheduled
+	 * next from this subtree.  By now we worry more about
+	 * correctness than about performance...
+	 */
+	next_active = bfq_lookup_next_entity(sd, 0);
+	sd->next_active = next_active;
+
+	if (next_active != NULL) {
+		bfqg = container_of(sd, struct bfq_group, sched_data);
+		entity = bfqg->my_entity;
+		if (entity != NULL)
+			entity->budget = next_active->budget;
+	}
+
+	return 1;
+}
+
+static inline void bfq_check_next_active(struct bfq_sched_data *sd,
+					 struct bfq_entity *entity)
+{
+	BUG_ON(sd->next_active != entity);
+}
+#else
+#define for_each_entity(entity)	\
+	for (; entity != NULL; entity = NULL)
+
+#define for_each_entity_safe(entity, parent) \
+	for (parent = NULL; entity != NULL; entity = parent)
+
+static inline int bfq_update_next_active(struct bfq_sched_data *sd)
+{
+	return 0;
+}
+
+static inline void bfq_check_next_active(struct bfq_sched_data *sd,
+					 struct bfq_entity *entity)
+{
+}
+#endif
+
+/*
+ * Shift for timestamp calculations.  This actually limits the maximum
+ * service allowed in one timestamp delta (small shift values increase it),
+ * the maximum total weight that can be used for the queues in the system
+ * (big shift values increase it), and the period of virtual time wraparounds.
+ */
+#define WFQ_SERVICE_SHIFT	22
+
+/**
+ * bfq_gt - compare two timestamps.
+ * @a: first ts.
+ * @b: second ts.
+ *
+ * Return @a > @b, dealing with wrapping correctly.
+ */
+static inline int bfq_gt(bfq_timestamp_t a, bfq_timestamp_t b)
+{
+	return (s64)(a - b) > 0;
+}
+
+/**
+ * bfq_delta - map service into the virtual time domain.
+ * @service: amount of service.
+ * @weight: scale factor.
+ */
+static inline bfq_timestamp_t bfq_delta(bfq_service_t service,
+					bfq_weight_t weight)
+{
+	bfq_timestamp_t d = (bfq_timestamp_t)service << WFQ_SERVICE_SHIFT;
+
+	do_div(d, weight);
+	return d;
+}
+
+/**
+ * bfq_calc_finish - assign the finish time to an entity.
+ * @entity: the entity to act upon.
+ * @service: the service to be charged to the entity.
+ */
+static inline void bfq_calc_finish(struct bfq_entity *entity,
+				   bfq_service_t service)
+{
+	BUG_ON(entity->weight == 0);
+
+	entity->finish = entity->start + bfq_delta(service, entity->weight);
+}
+
+/**
+ * bfq_entity_of - get an entity from a node.
+ * @node: the node field of the entity.
+ *
+ * Convert a node pointer to the relative entity.  This is used only
+ * to simplify the logic of some functions and not as the generic
+ * conversion mechanism because, e.g., in the tree walking functions,
+ * the check for a %NULL value would be redundant.
+ */
+static inline struct bfq_entity *bfq_entity_of(struct rb_node *node)
+{
+	struct bfq_entity *entity = NULL;
+
+	if (node != NULL)
+		entity = rb_entry(node, struct bfq_entity, rb_node);
+
+	return entity;
+}
+
+/**
+ * bfq_extract - remove an entity from a tree.
+ * @root: the tree root.
+ * @entity: the entity to remove.
+ */
+static inline void bfq_extract(struct rb_root *root,
+			       struct bfq_entity *entity)
+{
+	BUG_ON(entity->tree != root);
+
+	entity->tree = NULL;
+	rb_erase(&entity->rb_node, root);
+}
+
+static inline struct bfq_queue *bfq_entity_to_bfqq(struct bfq_entity *entity)
+{
+	struct bfq_queue *bfqq = NULL;
+
+	BUG_ON(entity == NULL);
+
+	if (entity->my_sched_data == NULL)
+		bfqq = container_of(entity, struct bfq_queue, entity);
+
+	return bfqq;
+}
+
+/**
+ * bfq_idle_extract - extract an entity from the idle tree.
+ * @st: the service tree of the owning @entity.
+ * @entity: the entity being removed.
+ */
+static void bfq_idle_extract(struct bfq_service_tree *st,
+			     struct bfq_entity *entity)
+{
+	struct bfq_queue *bfqq = bfq_entity_to_bfqq(entity);
+	struct rb_node *next;
+
+	BUG_ON(entity->tree != &st->idle);
+
+	if (entity == st->first_idle) {
+		next = rb_next(&entity->rb_node);
+		st->first_idle = bfq_entity_of(next);
+	}
+
+	if (entity == st->last_idle) {
+		next = rb_prev(&entity->rb_node);
+		st->last_idle = bfq_entity_of(next);
+	}
+
+	bfq_extract(&st->idle, entity);
+
+	if (bfqq != NULL)
+		list_del(&bfqq->bfqq_list);
+}
+
+/**
+ * bfq_insert - generic tree insertion.
+ * @root: tree root.
+ * @entity: entity to insert.
+ *
+ * This is used for the idle and the active tree, since they are both
+ * ordered by finish time.
+ */
+static void bfq_insert(struct rb_root *root, struct bfq_entity *entity)
+{
+	struct bfq_entity *entry;
+	struct rb_node **node = &root->rb_node;
+	struct rb_node *parent = NULL;
+
+	BUG_ON(entity->tree != NULL);
+
+	while (*node != NULL) {
+		parent = *node;
+		entry = rb_entry(parent, struct bfq_entity, rb_node);
+
+		if (bfq_gt(entry->finish, entity->finish))
+			node = &parent->rb_left;
+		else
+			node = &parent->rb_right;
+	}
+
+	rb_link_node(&entity->rb_node, parent, node);
+	rb_insert_color(&entity->rb_node, root);
+
+	entity->tree = root;
+}
+
+/**
+ * bfq_update_min - update the min_start field of a entity.
+ * @entity: the entity to update.
+ * @node: one of its children.
+ *
+ * This function is called when @entity may store an invalid value for
+ * min_start due to updates to the active tree.  The function  assumes
+ * that the subtree rooted at @node (which may be its left or its right
+ * child) has a valid min_start value.
+ */
+static inline void bfq_update_min(struct bfq_entity *entity,
+				  struct rb_node *node)
+{
+	struct bfq_entity *child;
+
+	if (node != NULL) {
+		child = rb_entry(node, struct bfq_entity, rb_node);
+		if (bfq_gt(entity->min_start, child->min_start))
+			entity->min_start = child->min_start;
+	}
+}
+
+/**
+ * bfq_update_active_node - recalculate min_start.
+ * @node: the node to update.
+ *
+ * @node may have changed position or one of its children may have moved,
+ * this function updates its min_start value.  The left and right subtrees
+ * are assumed to hold a correct min_start value.
+ */
+static inline void bfq_update_active_node(struct rb_node *node)
+{
+	struct bfq_entity *entity = rb_entry(node, struct bfq_entity, rb_node);
+
+	entity->min_start = entity->start;
+	bfq_update_min(entity, node->rb_right);
+	bfq_update_min(entity, node->rb_left);
+}
+
+/**
+ * bfq_update_active_tree - update min_start for the whole active tree.
+ * @node: the starting node.
+ *
+ * @node must be the deepest modified node after an update.  This function
+ * updates its min_start using the values held by its children, assuming
+ * that they did not change, and then updates all the nodes that may have
+ * changed in the path to the root.  The only nodes that may have changed
+ * are the ones in the path or their siblings.
+ */
+static void bfq_update_active_tree(struct rb_node *node)
+{
+	struct rb_node *parent;
+
+up:
+	bfq_update_active_node(node);
+
+	parent = rb_parent(node);
+	if (parent == NULL)
+		return;
+
+	if (node == parent->rb_left && parent->rb_right != NULL)
+		bfq_update_active_node(parent->rb_right);
+	else if (parent->rb_left != NULL)
+		bfq_update_active_node(parent->rb_left);
+
+	node = parent;
+	goto up;
+}
+
+/**
+ * bfq_active_insert - insert an entity in the active tree of its group/device.
+ * @st: the service tree of the entity.
+ * @entity: the entity being inserted.
+ *
+ * The active tree is ordered by finish time, but an extra key is kept
+ * per each node, containing the minimum value for the start times of
+ * its children (and the node itself), so it's possible to search for
+ * the eligible node with the lowest finish time in logarithmic time.
+ */
+static void bfq_active_insert(struct bfq_service_tree *st,
+			      struct bfq_entity *entity)
+{
+	struct bfq_queue *bfqq = bfq_entity_to_bfqq(entity);
+	struct rb_node *node = &entity->rb_node;
+
+	bfq_insert(&st->active, entity);
+
+	if (node->rb_left != NULL)
+		node = node->rb_left;
+	else if (node->rb_right != NULL)
+		node = node->rb_right;
+
+	bfq_update_active_tree(node);
+
+	if (bfqq != NULL)
+		list_add(&bfqq->bfqq_list, &bfqq->bfqd->active_list);
+}
+
+/**
+ * bfq_ioprio_to_weight - calc a weight from an ioprio.
+ * @ioprio: the ioprio value to convert.
+ */
+static bfq_weight_t bfq_ioprio_to_weight(int ioprio)
+{
+	WARN_ON(ioprio < 0 || ioprio >= IOPRIO_BE_NR);
+	return IOPRIO_BE_NR - ioprio;
+}
+
+static inline void bfq_get_entity(struct bfq_entity *entity)
+{
+	struct bfq_queue *bfqq = bfq_entity_to_bfqq(entity);
+	struct bfq_sched_data *sd;
+
+	if (bfqq != NULL) {
+		sd = entity->sched_data;
+		atomic_inc(&bfqq->ref);
+	}
+}
+
+/**
+ * bfq_find_deepest - find the deepest node that an extraction can modify.
+ * @node: the node being removed.
+ *
+ * Do the first step of an extraction in an rb tree, looking for the
+ * node that will replace @node, and returning the deepest node that
+ * the following modifications to the tree can touch.  If @node is the
+ * last node in the tree return %NULL.
+ */
+static struct rb_node *bfq_find_deepest(struct rb_node *node)
+{
+	struct rb_node *deepest;
+
+	if (node->rb_right == NULL && node->rb_left == NULL)
+		deepest = rb_parent(node);
+	else if (node->rb_right == NULL)
+		deepest = node->rb_left;
+	else if (node->rb_left == NULL)
+		deepest = node->rb_right;
+	else {
+		deepest = rb_next(node);
+		if (deepest->rb_right != NULL)
+			deepest = deepest->rb_right;
+		else if (rb_parent(deepest) != node)
+			deepest = rb_parent(deepest);
+	}
+
+	return deepest;
+}
+
+/**
+ * bfq_active_extract - remove an entity from the active tree.
+ * @st: the service_tree containing the tree.
+ * @entity: the entity being removed.
+ */
+static void bfq_active_extract(struct bfq_service_tree *st,
+			       struct bfq_entity *entity)
+{
+	struct bfq_queue *bfqq = bfq_entity_to_bfqq(entity);
+	struct rb_node *node;
+
+	node = bfq_find_deepest(&entity->rb_node);
+	bfq_extract(&st->active, entity);
+
+	if (node != NULL)
+		bfq_update_active_tree(node);
+
+	if (bfqq != NULL)
+		list_del(&bfqq->bfqq_list);
+}
+
+/**
+ * bfq_idle_insert - insert an entity into the idle tree.
+ * @st: the service tree containing the tree.
+ * @entity: the entity to insert.
+ */
+static void bfq_idle_insert(struct bfq_service_tree *st,
+			    struct bfq_entity *entity)
+{
+	struct bfq_queue *bfqq = bfq_entity_to_bfqq(entity);
+	struct bfq_entity *first_idle = st->first_idle;
+	struct bfq_entity *last_idle = st->last_idle;
+
+	if (first_idle == NULL || bfq_gt(first_idle->finish, entity->finish))
+		st->first_idle = entity;
+	if (last_idle == NULL || bfq_gt(entity->finish, last_idle->finish))
+		st->last_idle = entity;
+
+	bfq_insert(&st->idle, entity);
+
+	if (bfqq != NULL)
+		list_add(&bfqq->bfqq_list, &bfqq->bfqd->idle_list);
+}
+
+/**
+ * bfq_forget_entity - remove an entity from the wfq trees.
+ * @st: the service tree.
+ * @entity: the entity being removed.
+ *
+ * Update the device status and forget everything about @entity, putting
+ * the device reference to it, if it is a queue.  Entities belonging to
+ * groups are not refcounted.
+ */
+static void bfq_forget_entity(struct bfq_service_tree *st,
+			      struct bfq_entity *entity)
+{
+	struct bfq_queue *bfqq = bfq_entity_to_bfqq(entity);
+	struct bfq_sched_data *sd;
+
+	BUG_ON(!entity->on_st);
+
+	entity->on_st = 0;
+	st->wsum -= entity->weight;
+	if (bfqq != NULL) {
+		sd = entity->sched_data;
+		bfq_put_queue(bfqq);
+	}
+}
+
+/**
+ * bfq_put_idle_entity - release the idle tree ref of an entity.
+ * @st: service tree for the entity.
+ * @entity: the entity being released.
+ */
+static void bfq_put_idle_entity(struct bfq_service_tree *st,
+				struct bfq_entity *entity)
+{
+	bfq_idle_extract(st, entity);
+	bfq_forget_entity(st, entity);
+}
+
+/**
+ * bfq_forget_idle - update the idle tree if necessary.
+ * @st: the service tree to act upon.
+ *
+ * To preserve the global O(log N) complexity we only remove one entry here;
+ * as the idle tree will not grow indefinitely this can be done safely.
+ */
+static void bfq_forget_idle(struct bfq_service_tree *st)
+{
+	struct bfq_entity *first_idle = st->first_idle;
+	struct bfq_entity *last_idle = st->last_idle;
+
+	if (RB_EMPTY_ROOT(&st->active) && last_idle != NULL &&
+	    !bfq_gt(last_idle->finish, st->vtime)) {
+		/*
+		 * Forget the whole idle tree, increasing the vtime past
+		 * the last finish time of idle entities.
+		 */
+		st->vtime = last_idle->finish;
+	}
+
+	if (first_idle != NULL && !bfq_gt(first_idle->finish, st->vtime))
+		bfq_put_idle_entity(st, first_idle);
+}
+
+/**
+ * bfq_bfqq_served - update the scheduler status after selection for service.
+ * @bfqq: the queue being served.
+ * @served: bytes to transfer.
+ *
+ * NOTE: this can be optimized, as the timestamps of upper level entities
+ * are synchronized every time a new bfqq is selected for service.  By now,
+ * we keep it to better check consistency.
+ */
+static void bfq_bfqq_served(struct bfq_queue *bfqq, bfq_service_t served)
+{
+	struct bfq_entity *entity = &bfqq->entity;
+	struct bfq_service_tree *st;
+
+	for_each_entity(entity) {
+		st = bfq_entity_service_tree(entity);
+
+		entity->service += served;
+
+		WARN_ON_ONCE(entity->service > entity->budget);
+		BUG_ON(st->wsum == 0);
+
+		st->vtime += bfq_delta(served, st->wsum);
+		bfq_forget_idle(st);
+	}
+}
+
+/**
+ * bfq_bfqq_charge_full_budget - set the service to the entity budget.
+ * @bfqq: the queue that needs a service update.
+ *
+ * When it's not possible to be fair in the service domain, because
+ * a queue is not consuming its budget fast enough (the meaning of
+ * fast depends on the timeout parameter), we charge it a full
+ * budget.  In this way we should obtain a sort of time-domain
+ * fairness among all the seeky/slow queues.
+ */
+static void bfq_bfqq_charge_full_budget(struct bfq_queue *bfqq)
+{
+	struct bfq_entity *entity = &bfqq->entity;
+
+	bfq_bfqq_served(bfqq, entity->budget - entity->service);
+}
+
+static struct bfq_service_tree *
+__bfq_entity_update_prio(struct bfq_service_tree *old_st,
+			 struct bfq_entity *entity)
+{
+	struct bfq_service_tree *new_st = old_st;
+
+	if (entity->ioprio_changed) {
+		entity->ioprio = entity->new_ioprio;
+		entity->ioprio_class = entity->new_ioprio_class;
+		entity->ioprio_changed = 0;
+
+		old_st->wsum -= entity->weight;
+		entity->weight = bfq_ioprio_to_weight(entity->ioprio);
+
+		/*
+		 * NOTE: here we may be changing the weight too early,
+		 * this will cause unfairness.  The correct approach
+		 * would have required additional complexity to defer
+		 * weight changes to the proper time instants (i.e.,
+		 * when entity->finish <= old_st->vtime).
+		 */
+		new_st = bfq_entity_service_tree(entity);
+		new_st->wsum += entity->weight;
+
+		if (new_st != old_st)
+			entity->start = new_st->vtime;
+	}
+
+	return new_st;
+}
+
+/**
+ * __bfq_activate_entity - activate an entity.
+ * @entity: the entity being activated.
+ *
+ * Called whenever an entity is activated, i.e., it is not active and one
+ * of its children receives a new request, or has to be reactivated due to
+ * budget exhaustion.  It uses the current budget of the entity (and the
+ * service received if @entity is active) of the queue to calculate its
+ * timestamps.
+ */
+static void __bfq_activate_entity(struct bfq_entity *entity)
+{
+	struct bfq_sched_data *sd = entity->sched_data;
+	struct bfq_service_tree *st = bfq_entity_service_tree(entity);
+
+	if (entity == sd->active_entity) {
+		BUG_ON(entity->tree != NULL);
+		/*
+		 * If we are requeueing the current entity we have
+		 * to take care of not charging to it service it has
+		 * not received.
+		 */
+		bfq_calc_finish(entity, entity->service);
+		entity->start = entity->finish;
+		sd->active_entity = NULL;
+	} else if (entity->tree == &st->active) {
+		/*
+		 * Requeueing an entity due to a change of some
+		 * next_active entity below it.  We reuse the old
+		 * start time.
+		 */
+		bfq_active_extract(st, entity);
+	} else if (entity->tree == &st->idle) {
+		/*
+		 * Must be on the idle tree, bfq_idle_extract() will
+		 * check for that.
+		 */
+		bfq_idle_extract(st, entity);
+		entity->start = bfq_gt(st->vtime, entity->finish) ?
+				       st->vtime : entity->finish;
+	} else {
+		/*
+		 * The finish time of the entity may be invalid, and
+		 * it is in the past for sure, otherwise the queue
+		 * would have been on the idle tree.
+		 */
+		entity->start = st->vtime;
+		st->wsum += entity->weight;
+		bfq_get_entity(entity);
+
+		BUG_ON(entity->on_st);
+		entity->on_st = 1;
+	}
+
+	st = __bfq_entity_update_prio(st, entity);
+	bfq_calc_finish(entity, entity->budget);
+	bfq_active_insert(st, entity);
+}
+
+/**
+ * bfq_activate_entity - activate an entity and its ancestors if necessary.
+ * @entity: the entity to activate.
+ *
+ * Activate @entity and all the entities on the path from it to the root.
+ */
+static void bfq_activate_entity(struct bfq_entity *entity)
+{
+	struct bfq_sched_data *sd;
+
+	for_each_entity(entity) {
+		__bfq_activate_entity(entity);
+
+		sd = entity->sched_data;
+		if (!bfq_update_next_active(sd))
+			/*
+			 * No need to propagate the activation to the
+			 * upper entities, as they will be updated when
+			 * the active entity is rescheduled.
+			 */
+			break;
+	}
+}
+
+/**
+ * __bfq_deactivate_entity - deactivate an entity from its service tree.
+ * @entity: the entity to deactivate.
+ * @requeue: if false, the entity will not be put into the idle tree.
+ *
+ * Deactivate an entity, independently from its previous state.  If the
+ * entity was not on a service tree just return, otherwise if it is on
+ * any scheduler tree, extract it from that tree, and if necessary
+ * and if the caller did not specify @requeue, put it on the idle tree.
+ *
+ * Return %1 if the caller should update the entity hierarchy, i.e.,
+ * if the entity was under service or if it was the next_active for
+ * its sched_data; return %0 otherwise.
+ */
+static int __bfq_deactivate_entity(struct bfq_entity *entity, int requeue)
+{
+	struct bfq_sched_data *sd = entity->sched_data;
+	struct bfq_service_tree *st = bfq_entity_service_tree(entity);
+	int was_active = entity == sd->active_entity;
+	int ret = 0;
+
+	if (!entity->on_st)
+		return 0;
+
+	BUG_ON(was_active && entity->tree != NULL);
+
+	if (was_active) {
+		bfq_calc_finish(entity, entity->service);
+		sd->active_entity = NULL;
+	} else if (entity->tree == &st->active)
+		bfq_active_extract(st, entity);
+	else if (entity->tree == &st->idle)
+		bfq_idle_extract(st, entity);
+	else if (entity->tree != NULL)
+		BUG();
+
+	if (was_active || sd->next_active == entity)
+		ret = bfq_update_next_active(sd);
+
+	if (!requeue || !bfq_gt(entity->finish, st->vtime))
+		bfq_forget_entity(st, entity);
+	else
+		bfq_idle_insert(st, entity);
+
+	BUG_ON(sd->active_entity == entity);
+	BUG_ON(sd->next_active == entity);
+
+	return ret;
+}
+
+/**
+ * bfq_deactivate_entity - deactivate an entity.
+ * @entity: the entity to deactivate.
+ * @requeue: true if the entity can be put on the idle tree
+ */
+static void bfq_deactivate_entity(struct bfq_entity *entity, int requeue)
+{
+	struct bfq_sched_data *sd;
+	struct bfq_entity *parent;
+
+	for_each_entity_safe(entity, parent) {
+		sd = entity->sched_data;
+
+		if (!__bfq_deactivate_entity(entity, requeue))
+			/*
+			 * The parent entity is still backlogged, and
+			 * we don't need to update it as it is still
+			 * under service.
+			 */
+			break;
+
+		if (sd->next_active != NULL)
+			/*
+			 * The parent entity is still backlogged and
+			 * the budgets on the path towards the root
+			 * need to be updated.
+			 */
+			goto update;
+
+		/*
+		 * If we reach there the parent is no more backlogged and
+		 * we want to propagate the dequeue upwards.
+		 */
+		requeue = 1;
+	}
+
+	return;
+
+update:
+	entity = parent;
+	for_each_entity(entity) {
+		__bfq_activate_entity(entity);
+
+		sd = entity->sched_data;
+		if (!bfq_update_next_active(sd))
+			break;
+	}
+}
+
+/**
+ * bfq_update_vtime - update vtime if necessary.
+ * @st: the service tree to act upon.
+ *
+ * If necessary update the service tree vtime to have at least one
+ * eligible entity, skipping to its start time.  Assumes that the
+ * active tree of the device is not empty.
+ *
+ * NOTE: this hierarchical implementation updates vtimes quite often,
+ * we may end up with reactivated tasks getting timestamps after a
+ * vtime skip done because we needed a ->first_active entity on some
+ * intermediate node.
+ */
+static void bfq_update_vtime(struct bfq_service_tree *st)
+{
+	struct bfq_entity *entry;
+	struct rb_node *node = st->active.rb_node;
+
+	entry = rb_entry(node, struct bfq_entity, rb_node);
+	if (bfq_gt(entry->min_start, st->vtime)) {
+		st->vtime = entry->min_start;
+		bfq_forget_idle(st);
+	}
+}
+
+/**
+ * bfq_first_active - find the eligible entity with the smallest finish time
+ * @st: the service tree to select from.
+ *
+ * This function searches the first schedulable entity, starting from the
+ * root of the tree and going on the left every time on this side there is
+ * a subtree with at least one eligible (start >= vtime) entity.  The path
+ * on the right is followed only if a) the left subtree contains no eligible
+ * entities and b) no eligible entity has been found yet.
+ */
+static struct bfq_entity *bfq_first_active_entity(struct bfq_service_tree *st)
+{
+	struct bfq_entity *entry, *first = NULL;
+	struct rb_node *node = st->active.rb_node;
+
+	while (node != NULL) {
+		entry = rb_entry(node, struct bfq_entity, rb_node);
+left:
+		if (!bfq_gt(entry->start, st->vtime))
+			first = entry;
+
+		BUG_ON(bfq_gt(entry->min_start, st->vtime));
+
+		if (node->rb_left != NULL) {
+			entry = rb_entry(node->rb_left,
+					 struct bfq_entity, rb_node);
+			if (!bfq_gt(entry->min_start, st->vtime)) {
+				node = node->rb_left;
+				goto left;
+			}
+		}
+		if (first != NULL)
+			break;
+		node = node->rb_right;
+	}
+
+	BUG_ON(first == NULL && !RB_EMPTY_ROOT(&st->active));
+	return first;
+}
+
+/**
+ * __bfq_lookup_next_entity - return the first eligible entity in @st.
+ * @st: the service tree.
+ *
+ * Update the virtual time in @st and return the first eligible entity
+ * it contains.
+ */
+static struct bfq_entity *__bfq_lookup_next_entity(struct bfq_service_tree *st)
+{
+	struct bfq_entity *entity;
+
+	if (RB_EMPTY_ROOT(&st->active))
+		return NULL;
+
+	bfq_update_vtime(st);
+	entity = bfq_first_active_entity(st);
+	BUG_ON(bfq_gt(entity->start, st->vtime));
+
+	return entity;
+}
+
+/**
+ * bfq_lookup_next_entity - return the first eligible entity in @sd.
+ * @sd: the sched_data.
+ * @extract: if true the returned entity will be also extracted from @sd.
+ *
+ * NOTE: since we cache the next_active entity at each level of the
+ * hierarchy, the complexity of the lookup can be decreased with
+ * absolutely no effort just returning the cached next_active value;
+ * we prefer to do full lookups to test the consistency of * the data
+ * structures.
+ */
+static struct bfq_entity *bfq_lookup_next_entity(struct bfq_sched_data *sd,
+						 int extract)
+{
+	struct bfq_service_tree *st = sd->service_tree;
+	struct bfq_entity *entity;
+	int i;
+
+	BUG_ON(sd->active_entity != NULL);
+
+	for (i = 0; i < BFQ_IOPRIO_CLASSES; i++, st++) {
+		entity = __bfq_lookup_next_entity(st);
+		if (entity != NULL) {
+			if (extract) {
+				bfq_check_next_active(sd, entity);
+				bfq_active_extract(st, entity);
+				sd->active_entity = entity;
+				sd->next_active = NULL;
+			}
+			break;
+		}
+	}
+
+	return entity;
+}
+
+/*
+ * Get next queue for service.
+ */
+static struct bfq_queue *bfq_get_next_queue(struct bfq_data *bfqd)
+{
+	struct bfq_entity *entity = NULL;
+	struct bfq_sched_data *sd;
+	struct bfq_queue *bfqq;
+
+	BUG_ON(bfqd->active_queue != NULL);
+
+	if (bfqd->busy_queues == 0)
+		return NULL;
+
+	sd = &bfqd->root_group->sched_data;
+	for (; sd != NULL; sd = entity->my_sched_data) {
+		entity = bfq_lookup_next_entity(sd, 1);
+		BUG_ON(entity == NULL);
+		entity->service = 0;
+	}
+
+	bfqq = bfq_entity_to_bfqq(entity);
+	BUG_ON(bfqq == NULL);
+
+	return bfqq;
+}
+
+static void __bfq_bfqd_reset_active(struct bfq_data *bfqd)
+{
+	if (bfqd->active_cic != NULL) {
+		put_io_context(bfqd->active_cic->ioc);
+		bfqd->active_cic = NULL;
+	}
+
+	bfqd->active_queue = NULL;
+	del_timer(&bfqd->idle_slice_timer);
+}
+
+static void bfq_deactivate_bfqq(struct bfq_data *bfqd, struct bfq_queue *bfqq,
+				int requeue)
+{
+	struct bfq_entity *entity = &bfqq->entity;
+
+	if (bfqq == bfqd->active_queue)
+		__bfq_bfqd_reset_active(bfqd);
+
+	bfq_deactivate_entity(entity, requeue);
+}
+
+static void bfq_activate_bfqq(struct bfq_data *bfqd, struct bfq_queue *bfqq)
+{
+	struct bfq_entity *entity = &bfqq->entity;
+
+	bfq_activate_entity(entity);
+}
+
+/*
+ * Called when the bfqq no longer has requests pending, remove it from
+ * the service tree.
+ */
+static void bfq_del_bfqq_busy(struct bfq_data *bfqd, struct bfq_queue *bfqq,
+			      int requeue)
+{
+	BUG_ON(!bfq_bfqq_busy(bfqq));
+	BUG_ON(!RB_EMPTY_ROOT(&bfqq->sort_list));
+
+	bfq_log_bfqq(bfqd, bfqq, "del from busy");
+
+	bfq_clear_bfqq_busy(bfqq);
+
+	BUG_ON(bfqd->busy_queues == 0);
+	bfqd->busy_queues--;
+
+	bfq_deactivate_bfqq(bfqd, bfqq, requeue);
+}
+
+/*
+ * Called when an inactive queue receives a new request.
+ */
+static void bfq_add_bfqq_busy(struct bfq_data *bfqd, struct bfq_queue *bfqq)
+{
+	BUG_ON(bfq_bfqq_busy(bfqq));
+	BUG_ON(bfqq == bfqd->active_queue);
+
+	bfq_log_bfqq(bfqd, bfqq, "add to busy");
+
+	bfq_activate_bfqq(bfqd, bfqq);
+
+	bfq_mark_bfqq_busy(bfqq);
+	bfqd->busy_queues++;
+}
diff -Nru linux-source-2.6.28/block/blk-ioc.c linux-source-2.6.28-gs-bfq/block/blk-ioc.c
--- linux-source-2.6.28/block/blk-ioc.c	2008-12-25 00:26:37.000000000 +0100
+++ linux-source-2.6.28-gs-bfq/block/blk-ioc.c	2009-04-28 12:00:51.000000000 +0200
@@ -5,6 +5,7 @@
 #include <linux/module.h>
 #include <linux/init.h>
 #include <linux/bio.h>
+#include <linux/bitmap.h>
 #include <linux/blkdev.h>
 #include <linux/bootmem.h>	/* for max_pfn/max_low_pfn */
 
@@ -15,13 +16,12 @@
  */
 static struct kmem_cache *iocontext_cachep;
 
-static void cfq_dtor(struct io_context *ioc)
+static void hlist_sched_dtor(struct io_context *ioc, struct hlist_head *list)
 {
-	if (!hlist_empty(&ioc->cic_list)) {
+	if (!hlist_empty(list)) {
 		struct cfq_io_context *cic;
 
-		cic = list_entry(ioc->cic_list.first, struct cfq_io_context,
-								cic_list);
+		cic = list_entry(list->first, struct cfq_io_context, cic_list);
 		cic->dtor(ioc);
 	}
 }
@@ -41,7 +41,9 @@
 		rcu_read_lock();
 		if (ioc->aic && ioc->aic->dtor)
 			ioc->aic->dtor(ioc->aic);
-		cfq_dtor(ioc);
+
+		hlist_sched_dtor(ioc, &ioc->cic_list);
+		hlist_sched_dtor(ioc, &ioc->bfq_cic_list);
 		rcu_read_unlock();
 
 		kmem_cache_free(iocontext_cachep, ioc);
@@ -51,18 +53,18 @@
 }
 EXPORT_SYMBOL(put_io_context);
 
-static void cfq_exit(struct io_context *ioc)
+static void hlist_sched_exit(struct io_context *ioc, struct hlist_head *list)
 {
 	rcu_read_lock();
 
-	if (!hlist_empty(&ioc->cic_list)) {
+	if (!hlist_empty(list)) {
 		struct cfq_io_context *cic;
 
-		cic = list_entry(ioc->cic_list.first, struct cfq_io_context,
-								cic_list);
+		cic = list_entry(list->first, struct cfq_io_context, cic_list);
 		cic->exit(ioc);
 	}
 	rcu_read_unlock();
+
 }
 
 /* Called by the exitting task */
@@ -78,7 +80,8 @@
 	if (atomic_dec_and_test(&ioc->nr_tasks)) {
 		if (ioc->aic && ioc->aic->exit)
 			ioc->aic->exit(ioc->aic);
-		cfq_exit(ioc);
+		hlist_sched_exit(ioc, &ioc->cic_list);
+		hlist_sched_exit(ioc, &ioc->bfq_cic_list);
 
 		put_io_context(ioc);
 	}
@@ -93,13 +96,15 @@
 		atomic_set(&ret->refcount, 1);
 		atomic_set(&ret->nr_tasks, 1);
 		spin_lock_init(&ret->lock);
-		ret->ioprio_changed = 0;
+		bitmap_zero(ret->ioprio_changed, IOC_IOPRIO_CHANGED_BITS);
 		ret->ioprio = 0;
 		ret->last_waited = jiffies; /* doesn't matter... */
 		ret->nr_batch_requests = 0; /* because this is 0 */
 		ret->aic = NULL;
 		INIT_RADIX_TREE(&ret->radix_root, GFP_ATOMIC | __GFP_HIGH);
 		INIT_HLIST_HEAD(&ret->cic_list);
+		INIT_RADIX_TREE(&ret->bfq_radix_root, GFP_ATOMIC | __GFP_HIGH);
+		INIT_HLIST_HEAD(&ret->bfq_cic_list);
 		ret->ioc_data = NULL;
 	}
 
diff -Nru linux-source-2.6.28/block/cfq-iosched.c linux-source-2.6.28-gs-bfq/block/cfq-iosched.c
--- linux-source-2.6.28/block/cfq-iosched.c	2008-12-25 00:26:37.000000000 +0100
+++ linux-source-2.6.28-gs-bfq/block/cfq-iosched.c	2009-04-28 12:00:51.000000000 +0200
@@ -1425,7 +1425,6 @@
 static void cfq_ioc_set_ioprio(struct io_context *ioc)
 {
 	call_for_each_cic(ioc, changed_ioprio);
-	ioc->ioprio_changed = 0;
 }
 
 static struct cfq_queue *
@@ -1672,8 +1671,13 @@
 		goto err_free;
 
 out:
-	smp_read_barrier_depends();
-	if (unlikely(ioc->ioprio_changed))
+	/*
+	 * test_and_clear_bit() implies a memory barrier, paired with
+	 * the wmb() in fs/ioprio.c, so the value seen for ioprio is the
+	 * new one.
+	 */
+	if (unlikely(test_and_clear_bit(IOC_CFQ_IOPRIO_CHANGED,
+					ioc->ioprio_changed)))
 		cfq_ioc_set_ioprio(ioc);
 
 	return cic;
diff -Nru linux-source-2.6.28/block/Kconfig.iosched linux-source-2.6.28-gs-bfq/block/Kconfig.iosched
--- linux-source-2.6.28/block/Kconfig.iosched	2008-12-25 00:26:37.000000000 +0100
+++ linux-source-2.6.28-gs-bfq/block/Kconfig.iosched	2009-04-28 12:01:18.000000000 +0200
@@ -40,6 +40,27 @@
 	  working environment, suitable for desktop systems.
 	  This is the default I/O scheduler.
 
+config IOSCHED_BFQ
+	tristate "BFQ I/O scheduler"
+	depends on EXPERIMENTAL
+	default n
+	---help---
+	  The BFQ I/O scheduler tries to distribute bandwidth among
+	  all processes in the system, according to their weights,
+	  which can be set using task ioprio values.  It aims at giving
+	  deterministic guarantees on the distribution of the service
+	  provided.  If compiled built-in (saying Y here), BFQ can
+	  be configured to support hierarchical scheduling.
+
+config CGROUP_BFQIO
+	bool "BFQ hierarchical scheduling support"
+	depends on CGROUPS && IOSCHED_BFQ=y
+	default n
+	---help---
+	  Enable hierarchical scheduling in BFQ, using the cgroups
+	  filesystem interface.  The name of the subsystem will be
+	  bfqio.
+
 choice
 	prompt "Default I/O scheduler"
 	default DEFAULT_CFQ
@@ -56,6 +77,9 @@
 	config DEFAULT_CFQ
 		bool "CFQ" if IOSCHED_CFQ=y
 
+	config DEFAULT_BFQ
+		bool "BFQ" if IOSCHED_BFQ=y
+
 	config DEFAULT_NOOP
 		bool "No-op"
 
@@ -66,6 +90,7 @@
 	default "anticipatory" if DEFAULT_AS
 	default "deadline" if DEFAULT_DEADLINE
 	default "cfq" if DEFAULT_CFQ
+	default "bfq" if DEFAULT_BFQ
 	default "noop" if DEFAULT_NOOP
 
 endmenu
diff -Nru linux-source-2.6.28/block/Makefile linux-source-2.6.28-gs-bfq/block/Makefile
--- linux-source-2.6.28/block/Makefile	2008-12-25 00:26:37.000000000 +0100
+++ linux-source-2.6.28-gs-bfq/block/Makefile	2009-04-28 12:01:18.000000000 +0200
@@ -12,6 +12,7 @@
 obj-$(CONFIG_IOSCHED_AS)	+= as-iosched.o
 obj-$(CONFIG_IOSCHED_DEADLINE)	+= deadline-iosched.o
 obj-$(CONFIG_IOSCHED_CFQ)	+= cfq-iosched.o
+obj-$(CONFIG_IOSCHED_BFQ)	+= bfq-iosched.o
 
 obj-$(CONFIG_BLK_DEV_IO_TRACE)	+= blktrace.o
 obj-$(CONFIG_BLOCK_COMPAT)	+= compat_ioctl.o
diff -Nru linux-source-2.6.28/fs/ioprio.c linux-source-2.6.28-gs-bfq/fs/ioprio.c
--- linux-source-2.6.28/fs/ioprio.c	2009-04-17 03:57:42.000000000 +0200
+++ linux-source-2.6.28-gs-bfq/fs/ioprio.c	2009-04-28 12:00:51.000000000 +0200
@@ -29,7 +29,7 @@
 
 static int set_task_ioprio(struct task_struct *task, int ioprio)
 {
-	int err;
+	int err, i;
 	struct io_context *ioc;
 
 	if (task->uid != current->euid &&
@@ -53,12 +53,17 @@
 			err = -ENOMEM;
 			break;
 		}
+		/* let other ioc users see the new values */
+		smp_wmb();
 		task->io_context = ioc;
 	} while (1);
 
 	if (!err) {
 		ioc->ioprio = ioprio;
-		ioc->ioprio_changed = 1;
+		/* make sure schedulers see the new ioprio value */
+		wmb();
+		for (i = 0; i < IOC_IOPRIO_CHANGED_BITS; i++)
+			set_bit(i, ioc->ioprio_changed);
 	}
 
 	task_unlock(task);
diff -Nru linux-source-2.6.28/include/linux/cgroup_subsys.h linux-source-2.6.28-gs-bfq/include/linux/cgroup_subsys.h
--- linux-source-2.6.28/include/linux/cgroup_subsys.h	2008-12-25 00:26:37.000000000 +0100
+++ linux-source-2.6.28-gs-bfq/include/linux/cgroup_subsys.h	2009-04-28 12:01:18.000000000 +0200
@@ -54,3 +54,9 @@
 #endif
 
 /* */
+
+#ifdef CONFIG_CGROUP_BFQIO
+SUBSYS(bfqio)
+#endif
+
+/* */
diff -Nru linux-source-2.6.28/include/linux/init_task.h linux-source-2.6.28-gs-bfq/include/linux/init_task.h
--- linux-source-2.6.28/include/linux/init_task.h	2008-12-25 00:26:37.000000000 +0100
+++ linux-source-2.6.28-gs-bfq/include/linux/init_task.h	2009-04-25 09:44:01.000000000 +0200
@@ -113,6 +113,12 @@
 # define CAP_INIT_BSET  CAP_INIT_EFF_SET
 #endif
 
+#ifdef CONFIG_GENERIC_SCHEDULER
+#define INIT_GENSCHED_DATA .private_data = NULL,
+#else
+#define INIT_GENSCHED_DATA
+#endif
+
 /*
  *  INIT_TASK is used to set up the first task table, touch at
  * your own risk!. Base=0, limit=0x1fffff (=2MB)
@@ -177,6 +183,7 @@
 		[PIDTYPE_SID]  = INIT_PID_LINK(PIDTYPE_SID),		\
 	},								\
 	.dirties = INIT_PROP_LOCAL_SINGLE(dirties),			\
+	INIT_GENSCHED_DATA						\
 	INIT_IDS							\
 	INIT_TRACE_IRQFLAGS						\
 	INIT_LOCKDEP							\
diff -Nru linux-source-2.6.28/include/linux/iocontext.h linux-source-2.6.28-gs-bfq/include/linux/iocontext.h
--- linux-source-2.6.28/include/linux/iocontext.h	2008-12-25 00:26:37.000000000 +0100
+++ linux-source-2.6.28-gs-bfq/include/linux/iocontext.h	2009-04-28 12:00:51.000000000 +0200
@@ -1,6 +1,7 @@
 #ifndef IOCONTEXT_H
 #define IOCONTEXT_H
 
+#include <linux/bitmap.h>
 #include <linux/radix-tree.h>
 #include <linux/rcupdate.h>
 
@@ -30,12 +31,11 @@
 	sector_t seek_mean;
 };
 
-struct cfq_queue;
 struct cfq_io_context {
 	void *key;
 	unsigned long dead_key;
 
-	struct cfq_queue *cfqq[2];
+	void *cfqq[2];
 
 	struct io_context *ioc;
 
@@ -60,6 +60,16 @@
 };
 
 /*
+ * Indexes into the ioprio_changed bitmap.  A bit set indicates that
+ * the corresponding I/O scheduler needs to see a ioprio update.
+ */
+enum {
+	IOC_CFQ_IOPRIO_CHANGED,
+	IOC_BFQ_IOPRIO_CHANGED,
+	IOC_IOPRIO_CHANGED_BITS
+};
+
+/*
  * I/O subsystem state of the associated processes.  It is refcounted
  * and kmalloc'ed. These could be shared between processes.
  */
@@ -71,7 +81,7 @@
 	spinlock_t lock;
 
 	unsigned short ioprio;
-	unsigned short ioprio_changed;
+	DECLARE_BITMAP(ioprio_changed, IOC_IOPRIO_CHANGED_BITS);
 
 	/*
 	 * For request batching
@@ -82,6 +92,8 @@
 	struct as_io_context *aic;
 	struct radix_tree_root radix_root;
 	struct hlist_head cic_list;
+	struct radix_tree_root bfq_radix_root;
+	struct hlist_head bfq_cic_list;
 	void *ioc_data;
 };
 
diff -Nru linux-source-2.6.28/include/linux/sched.h linux-source-2.6.28-gs-bfq/include/linux/sched.h
--- linux-source-2.6.28/include/linux/sched.h	2009-04-17 03:57:42.000000000 +0200
+++ linux-source-2.6.28-gs-bfq/include/linux/sched.h	2009-04-25 09:44:01.000000000 +0200
@@ -1332,6 +1332,10 @@
 	atomic_t fs_excl;	/* holding fs exclusive resources */
 	struct rcu_head rcu;
 
+#ifdef CONFIG_GENERIC_SCHEDULER
+	void *private_data;
+#endif
+
 	/*
 	 * cache last used pipe for splice
 	 */
@@ -2172,6 +2176,19 @@
 
 extern void signal_wake_up(struct task_struct *t, int resume_stopped);
 
+#ifdef CONFIG_GENERIC_SCHEDULER
+extern void (*block_hook)(struct task_struct *tsk);
+extern void (*unblock_hook)(struct task_struct *tsk, long old_state);
+extern void (*stop_hook)(struct task_struct *tsk);
+extern void (*continue_hook)(struct task_struct *tsk, long old_state);
+extern void (*fork_hook)(struct task_struct *tsk, struct task_struct *prev);
+extern void (*cleanup_hook)(struct task_struct *tsk);
+extern void (*switch_hook)(struct task_struct *prev, struct task_struct *next);
+extern void set_task_rr_prio(struct task_struct *p, int priority);
+
+extern rwlock_t hook_lock;
+#endif
+
 /*
  * Wrappers for p->thread_info->cpu access. No-op on UP.
  */
diff -Nru linux-source-2.6.28/kernel/exit.c linux-source-2.6.28-gs-bfq/kernel/exit.c
--- linux-source-2.6.28/kernel/exit.c	2009-04-17 03:57:42.000000000 +0200
+++ linux-source-2.6.28-gs-bfq/kernel/exit.c	2009-04-25 09:44:01.000000000 +0200
@@ -53,6 +53,11 @@
 #include <asm/pgtable.h>
 #include <asm/mmu_context.h>
 
+#ifdef CONFIG_GENERIC_SCHEDULER
+void (*cleanup_hook)(struct task_struct *tsk);
+EXPORT_SYMBOL_GPL(cleanup_hook);
+#endif
+
 static void exit_mm(struct task_struct * tsk);
 
 static inline int task_detached(struct task_struct *p)
@@ -1046,7 +1051,12 @@
 		printk(KERN_INFO "note: %s[%d] exited with preempt_count %d\n",
 				current->comm, task_pid_nr(current),
 				preempt_count());
-
+#ifdef CONFIG_GENERIC_SCHEDULER
+	read_lock(&hook_lock);
+	if (cleanup_hook != NULL && tsk->private_data != NULL)
+		cleanup_hook(tsk);
+	read_unlock(&hook_lock);
+#endif
 	acct_update_integrals(tsk);
 	if (tsk->mm) {
 		update_hiwater_rss(tsk->mm);
diff -Nru linux-source-2.6.28/kernel/fork.c linux-source-2.6.28-gs-bfq/kernel/fork.c
--- linux-source-2.6.28/kernel/fork.c	2009-04-17 03:57:42.000000000 +0200
+++ linux-source-2.6.28-gs-bfq/kernel/fork.c	2009-04-25 09:44:01.000000000 +0200
@@ -79,6 +79,7 @@
 DEFINE_PER_CPU(unsigned long, process_counts) = 0;
 
 __cacheline_aligned DEFINE_RWLOCK(tasklist_lock);  /* outer */
+EXPORT_SYMBOL(tasklist_lock);
 
 int nr_processes(void)
 {
@@ -977,6 +978,10 @@
 	if (!p)
 		goto fork_out;
 
+#ifdef CONFIG_GENERIC_SCHEDULER
+	p->private_data = NULL;
+#endif
+
 	rt_mutex_init_task(p);
 
 #ifdef CONFIG_PROVE_LOCKING
diff -Nru linux-source-2.6.28/kernel/sched.c linux-source-2.6.28-gs-bfq/kernel/sched.c
--- linux-source-2.6.28/kernel/sched.c	2009-04-17 03:57:42.000000000 +0200
+++ linux-source-2.6.28-gs-bfq/kernel/sched.c	2009-04-28 16:36:40.000000000 +0200
@@ -79,6 +79,31 @@
 
 #include "sched_cpupri.h"
 
+#include <linux/sched.h>
+
+#ifdef CONFIG_GENERIC_SCHEDULER
+void (*block_hook)(struct task_struct *tsk);
+EXPORT_SYMBOL(block_hook);
+
+void (*unblock_hook)(struct task_struct *tsk, long old_state);
+EXPORT_SYMBOL(unblock_hook);
+
+void (*stop_hook)(struct task_struct *tsk);
+EXPORT_SYMBOL(stop_hook);
+
+void (*continue_hook)(struct task_struct *tsk, long old_state);
+EXPORT_SYMBOL(continue_hook);
+
+void (*fork_hook)(struct task_struct *tsk, struct task_struct *prev);
+EXPORT_SYMBOL(fork_hook);
+
+void (*switch_hook)(struct task_struct *prev, struct task_struct *next);
+EXPORT_SYMBOL(switch_hook);
+
+rwlock_t hook_lock __cacheline_aligned = RW_LOCK_UNLOCKED;
+EXPORT_SYMBOL(hook_lock);
+#endif /* CONFIG_GENERIC_SCHEDULER */
+
 /*
  * Convert user-nice values [ -20 ... 0 ... 19 ]
  * to static priority [ MAX_RT_PRIO..MAX_PRIO-1 ],
@@ -2329,6 +2354,22 @@
 
 	task_rq_unlock(rq, &flags);
 
+#ifdef CONFIG_GENERIC_SCHEDULER
+	if ((success == 1) && (old_state & TASK_STOPPED)) {
+		read_lock(&hook_lock);
+		if ((continue_hook != NULL) && (p->private_data != NULL))
+			continue_hook(p, old_state);
+
+		read_unlock(&hook_lock);
+	} else if ((success == 1) && (old_state < TASK_STOPPED)) {
+		read_lock(&hook_lock);
+		if ((unblock_hook != NULL) && (p->private_data != NULL))
+			unblock_hook(p, old_state);
+
+		read_unlock(&hook_lock);
+	}
+#endif
+
 	return success;
 }
 
@@ -2609,6 +2650,13 @@
 #endif
 	if (current->set_child_tid)
 		put_user(task_pid_vnr(current), current->set_child_tid);
+
+#ifdef CONFIG_GENERIC_SCHEDULER
+	read_lock(&hook_lock);
+	if (prev->private_data != NULL && fork_hook != NULL)
+		fork_hook(current, prev);
+	read_unlock(&hook_lock);
+#endif
 }
 
 /*
@@ -2666,6 +2714,47 @@
 }
 
 /*
+ * activate_task_local - activate a task on the local CPU
+ * The caller must be sure that p cannot disappear.  The old code
+ * seemed not to assume this.
+ */
+void activate_task_local(struct task_struct *p) {
+	unsigned long flags;
+	struct rq *rq;
+
+	rq = task_rq_lock(p, &flags);
+
+	if (!p->se.on_rq)
+		activate_task(rq, p, 0);
+
+	check_preempt_curr(rq, p, 0);
+
+	task_rq_unlock(rq, &flags);
+}
+EXPORT_SYMBOL(activate_task_local);
+
+/*
+ * deactivate_task_local - deactivate a task on the local CPU
+ * The caller must be sure that p cannot disappear.  The old code
+ * seemed not to assume this.
+ */
+void deactivate_task_local(struct task_struct *p) {
+	unsigned long flags;
+	struct rq *rq;
+
+	rq = task_rq_lock(p, &flags);
+
+	if (p->se.on_rq)
+		deactivate_task(rq, p, 0);
+
+	if (rq->curr == p)
+		resched_task(rq->curr);
+
+	task_rq_unlock(rq, &flags);
+}
+EXPORT_SYMBOL(deactivate_task_local);
+
+/*
  * nr_running, nr_uninterruptible and nr_context_switches:
  *
  * externally visible scheduler statistics: current number of runnable
@@ -4411,6 +4500,24 @@
 	const struct sched_class *class;
 	struct task_struct *p;
 
+#ifdef CONFIG_GENERIC_SCHEDULER
+	read_lock(&hook_lock);
+
+	if (prev->state && !(preempt_count() & PREEMPT_ACTIVE)) {
+		if (unlikely(signal_pending_state(prev->state, prev))) {
+		} else {
+			if ((stop_hook != NULL) && (prev->private_data != NULL)
+			    && (prev->state & TASK_STOPPED))
+				stop_hook(prev);
+			else if ((block_hook != NULL) &&
+				 (prev->private_data != NULL))
+				block_hook(prev);
+		}
+	}
+
+	read_unlock(&hook_lock);
+#endif
+
 	/*
 	 * Optimization: we know that if all tasks are in
 	 * the fair class we can call that function directly:
@@ -4486,6 +4593,14 @@
 	if (likely(prev != next)) {
 		sched_info_switch(prev, next);
 
+#ifdef CONFIG_GENERIC_SCHEDULER
+		read_lock(&hook_lock);
+		if (switch_hook &&
+		    (prev->private_data != NULL || next->private_data != NULL))
+			switch_hook(prev, next);
+		read_unlock(&hook_lock);
+#endif
+
 		rq->nr_switches++;
 		rq->curr = next;
 		++*switch_count;
@@ -5289,6 +5404,28 @@
 	return __sched_setscheduler(p, policy, param, false);
 }
 
+#ifdef CONFIG_GENERIC_SCHEDULER
+/*
+ * If priority != 0, then set policy to SCHED_RR and prio to priority.
+ * else, set policy to SCHED_NORMAL and prio to 0.
+ */
+void set_task_rr_prio(struct task_struct *p, int priority)
+{
+	struct sched_param sp;
+	int policy;
+
+	if (priority > 0) {
+		sp.sched_priority = priority;
+		policy = SCHED_RR;
+	} else {
+		sp.sched_priority = 0;
+		policy = SCHED_NORMAL;
+	}
+	sched_setscheduler_nocheck(p, policy, &sp);
+}
+EXPORT_SYMBOL_GPL(set_task_rr_prio);
+#endif
+
 static int
 do_sched_setscheduler(pid_t pid, int policy, struct sched_param __user *param)
 {
diff -Nru linux-source-2.6.28/Makefile linux-source-2.6.28-gs-bfq/Makefile
--- linux-source-2.6.28/Makefile	2009-04-17 03:57:42.000000000 +0200
+++ linux-source-2.6.28-gs-bfq/Makefile	2009-04-25 09:44:57.000000000 +0200
@@ -4,6 +4,9 @@
 EXTRAVERSION = .9
 NAME = Erotic Pickled Herring
 
+GENSCHED_VERSION = 3
+GENSCHED_REVISION = 1
+
 # *DOCUMENTATION*
 # To see a list of typical targets execute "make help"
 # More info can be located in ./README
@@ -1024,9 +1027,12 @@
 endef
 
 define filechk_version.h
-	(echo \#define LINUX_VERSION_CODE $(shell                             \
-	expr $(VERSION) \* 65536 + $(PATCHLEVEL) \* 256 + $(SUBLEVEL));     \
-	echo '#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))';)
+	(echo \#define LINUX_VERSION_CODE $(shell                                   \
+	expr $(VERSION) \* 65536 + $(PATCHLEVEL) \* 256 + $(SUBLEVEL));             \
+	echo '#define KERNEL_VERSION(a,b,c) (((a) << 16) + ((b) << 8) + (c))';      \
+	echo \#define GENSCHED_VERSION_CODE $(shell                                 \
+	expr $(GENSCHED_VERSION) \* 65536 + $(GENSCHED_REVISION) \* 256);           \
+	echo '#define GENSCHED_VERSION(a,b) (((a) << 16) + ((b) << 8))';)
 endef
 
 include/linux/version.h: $(srctree)/Makefile FORCE

